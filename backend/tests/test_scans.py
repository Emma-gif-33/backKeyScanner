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
async def test_scans_ingestion_lifecycle():
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

        # 2. Upload valid zip file
        mock_zip_bytes = create_mock_zip({
            "app.py": "print('hello world')",
            "utils/helper.py": "def test(): return True",
            "requirements.txt": "fastapi==0.115.0\nrequests==2.31.0"
        })

        upload_res = await client.post(
            "/api/v1/scans/upload",
            headers=headers,
            data={"project_name": "My Sample Project"},
            files={"file": ("sample_repo.zip", mock_zip_bytes, "application/zip")}
        )
        assert upload_res.status_code == 201, upload_res.text
        scan_data = upload_res.json()
        assert scan_data["project_name"] == "My Sample Project"
        assert scan_data["status"] == "QUEUED"
        assert len(scan_data["file_hash_sha256"]) == 64
        assert scan_data["summary_metrics"]["files_extracted"] == 3
        scan_id = scan_data["id"]

        # 3. Retrieve scan details
        detail_res = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert detail_res.status_code == 200
        assert detail_res.json()["id"] == scan_id

        # 4. List user scans
        list_res = await client.get("/api/v1/scans", headers=headers)
        assert list_res.status_code == 200
        scans_list = list_res.json()["scans"]
        assert any(s["id"] == scan_id for s in scans_list)

        # 5. Reject non-zip uploads
        bad_file_res = await client.post(
            "/api/v1/scans/upload",
            headers=headers,
            files={"file": ("malicious.exe", b"fake binary data", "application/octet-stream")}
        )
        assert bad_file_res.status_code == 400

        # 6. Reject corrupt zip uploads
        corrupt_res = await client.post(
            "/api/v1/scans/upload",
            headers=headers,
            files={"file": ("corrupt.zip", b"PK\x03\x04corruptedbytes12345", "application/zip")}
        )
        assert corrupt_res.status_code == 400

        # 7. Reject Zip Slip path traversal attack
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
        assert "Zip Slip" in slip_res.json()["detail"] or "traversal" in slip_res.json()["detail"].lower()

        # 8. Delete scan
        del_res = await client.delete(f"/api/v1/scans/{scan_id}", headers=headers)
        assert del_res.status_code == 204

        # Confirm 404 after deletion
        check_del_res = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert check_del_res.status_code == 404
