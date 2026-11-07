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
    # 1. Setup authenticated user
    user_email = f"scanuser_{uuid.uuid4().hex[:8]}@example.com"
    password = "SecurePassword123!"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Register and login
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

        # 2. Upload zip containing exposed secrets
        mock_zip_bytes = create_mock_zip({
            "src/settings.py": 'AWS_ACCESS = "AKIA1234567890EXAMPL"\nDB_URL = "postgres://root:SuperSecret123@db:5432/app"',
            "config/keys.json": '{\n  "github_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n}',
            "clean_code.py": 'def add(a, b):\n    return a + b\n'
        })

        upload_res = await client.post(
            "/api/v1/scans/upload",
            headers=headers,
            data={"project_name": "Secret Testing Project"},
            files={"file": ("vulnerable_app.zip", mock_zip_bytes, "application/zip")}
        )
        assert upload_res.status_code == 201, upload_res.text
        scan_data = upload_res.json()
        scan_id = scan_data["id"]
        assert scan_data["total_secrets"] == 0
        assert scan_data["risk_level"] == "NONE"

        # 3. Trigger secret scan
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

        # Ensure all findings are masked and have tips
        for f in findings:
            assert "*" in f["masked_snippet"]
            assert f["remediation_tip"] is not None
            assert f["scan_id"] == scan_id

        # 4. Check updated scan details (total_secrets and risk_level)
        updated_scan = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert updated_scan.status_code == 200
        scan_info = updated_scan.json()
        assert scan_info["total_secrets"] >= 3
        assert scan_info["risk_level"] == "CRITICAL"

        # 5. Query secrets endpoint
        stored_secrets = await client.get(f"/api/v1/scans/{scan_id}/secrets", headers=headers)
        assert stored_secrets.status_code == 200
        assert len(stored_secrets.json()) == len(findings)

        # 6. Reject Zip Slip path traversal attack
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

        # 7. Cleanup / Delete scan
        del_res = await client.delete(f"/api/v1/scans/{scan_id}", headers=headers)
        assert del_res.status_code == 204
