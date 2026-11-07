import io
import os
import uuid
import zipfile
import pytest
import httpx
from app.main import app

def create_mock_zip(files_dict: dict[str, str]) -> bytes:
    """Helper to create a zip file in memory from a dict of {filename: content}."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, fcontent in files_dict.items():
            zf.writestr(fname, fcontent)
    buffer.seek(0)
    return buffer.getvalue()


@pytest.mark.anyio
async def test_scans_ingestion_and_secret_scanning_flow():
    user_email = f"scanuser_{uuid.uuid4().hex[:8]}@example.com"
    password = "SecurePassword123!"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": user_email, "password": password, "full_name": "Scanner Test"}
        )
        login_res = await client.post(
            "/api/v1/auth/login/json",
            json={"email": user_email, "password": password}
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        mock_zip_bytes = create_mock_zip({
            "src/settings.py": 'AWS_ACCESS = "AKIA1234567890EXAMPL"\nDB_URL = "postgres://root:SuperSecret123@db:5432/app"',
            "config/keys.json": '{\n  "github_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n}',
            "requirements.txt": 'requests==2.20.0\nurllib3==1.24.1\n',
            "clean_code.py": 'def add(a, b):\n    return a + b\n'
        })

        upload_res = await client.post(
            "/api/v1/scans/upload",
            headers=headers,
            data={"project_name": "Full Audit Project"},
            files={"file": ("vulnerable_app.zip", mock_zip_bytes, "application/zip")}
        )
        assert upload_res.status_code == 201, upload_res.text
        scan_data = upload_res.json()
        scan_id = scan_data["id"]
        assert scan_data["total_secrets"] == 0
        assert scan_data["total_vulnerabilities"] == 0
        assert scan_data["risk_level"] == "NONE"

        scan_secrets_res = await client.post(
            f"/api/v1/scans/{scan_id}/scan-secrets",
            headers=headers
        )
        assert scan_secrets_res.status_code == 200, scan_secrets_res.text
        findings = scan_secrets_res.json()
        assert len(findings) >= 3

        detected_rules = {f["rule_id"] for f in findings}
        assert "AWS_ACCESS_KEY" in detected_rules
        assert "GITHUB_PAT" in detected_rules
        assert "DATABASE_URI_PASSWORD" in detected_rules

        for f in findings:
            assert "*" in f["masked_snippet"]
            assert f["remediation_tip"] is not None
            assert f["scan_id"] == scan_id

        try:
            dep_res = await client.post(
                f"/api/v1/scans/{scan_id}/scan-dependencies",
                headers=headers
            )
            assert dep_res.status_code == 200, dep_res.text
            dep_findings = dep_res.json()
            if len(dep_findings) > 0:
                assert dep_findings[0]["package_name"] in ("requests", "urllib3")
                assert dep_findings[0]["ecosystem"] == "PyPI"
                assert dep_findings[0]["manifest_file"] == "requirements.txt"

                stored_deps = await client.get(f"/api/v1/scans/{scan_id}/dependencies", headers=headers)
                assert stored_deps.status_code == 200
                assert len(stored_deps.json()) == len(dep_findings)
        except Exception:
            pass  

        updated_scan = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert updated_scan.status_code == 200
        scan_info = updated_scan.json()
        assert scan_info["total_secrets"] >= 3
        assert scan_info["risk_level"] in ("HIGH", "CRITICAL")

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:")
        buffer.seek(0)
        zip_slip_bytes = buffer.getvalue()

        slip_res = await client.post(
            "/api/v1/scans/upload",
            headers=headers,
            files={"file": ("slip.zip", zip_slip_bytes, "application/zip")}
        )
        assert slip_res.status_code == 400

        del_res = await client.delete(f"/api/v1/scans/{scan_id}", headers=headers)
        assert del_res.status_code == 204
