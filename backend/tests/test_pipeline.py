import io
import uuid
import zipfile
import pytest
import httpx
from app.main import app
from app.services.scanner_pipeline import run_full_scan_pipeline

def create_mock_zip(files_dict: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, fcontent in files_dict.items():
            zf.writestr(fname, fcontent)
    buffer.seek(0)
    return buffer.getvalue()


@pytest.mark.anyio
async def test_full_pipeline_and_consolidated_report():
    user_email = f"pipeline_{uuid.uuid4().hex[:8]}@example.com"
    password = "SuperPassword123!"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": user_email, "password": password, "full_name": "Pipeline Tester"}
        )
        login_res = await client.post(
            "/api/v1/auth/login/json",
            json={"email": user_email, "password": password}
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        mock_zip_bytes = create_mock_zip({
            ".env": "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nDATABASE_URL=postgres://app_user:SecretDBPass123@db.prod:5432/main",
            "package.json": '{\n  "name": "node-vulnerable-test",\n  "dependencies": {\n    "lodash": "4.17.15",\n    "axios": "0.21.1"\n  }\n}',
            "src/index.js": 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";\nconsole.log(token);'
        })

        upload_res = await client.post(
            "/api/v1/scans/upload",
            headers=headers,
            data={"project_name": "Node and Secrets Audit"},
            files={"file": ("project_bundle.zip", mock_zip_bytes, "application/zip")}
        )
        assert upload_res.status_code == 201
        scan_id = upload_res.json()["id"]

        await run_full_scan_pipeline(uuid.UUID(scan_id))

        report_res = await client.get(f"/api/v1/scans/{scan_id}/report", headers=headers)
        assert report_res.status_code == 200, report_res.text
        report = report_res.json()

        assert report["scan_id"] == scan_id
        assert report["project_name"] == "Node and Secrets Audit"
        assert report["status"] == "COMPLETED"
        assert report["risk_level"] in ("HIGH", "CRITICAL")
        assert report["started_at"] is not None
        assert report["finished_at"] is not None

        summary = report["summary"]
        assert summary["total_findings"] > 0
        assert summary["by_category"]["secrets"] >= 2  # AWS key, DB URI, GitHub token
        assert "by_severity" in summary
        assert summary["by_severity"]["critical"] >= 1

        secrets = report["secrets"]
        assert len(secrets) >= 2
        for s in secrets:
            assert "*" in s["masked_snippet"]
            assert s["remediation_tip"] is not None
            assert "AKIAIOSFODNN7EXAMPLE" not in s["masked_snippet"]

        deps = report["dependencies"]
        if len(deps) > 0:
            assert any(d["package_name"] in ("lodash", "axios") for d in deps)
            assert any(d["ecosystem"] == "npm" for d in deps)
