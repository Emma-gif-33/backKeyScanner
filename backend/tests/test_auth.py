import pytest
import uuid
import httpx
from app.main import app

@pytest.mark.anyio
async def test_full_auth_flow():
    # Use a random unique email for test isolation
    unique_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    password = "SuperSecurePassword123"
    full_name = "Emma Test User"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register a new user
        reg_response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": unique_email,
                "password": password,
                "full_name": full_name
            }
        )
        assert reg_response.status_code == 201, reg_response.text
        user_data = reg_response.json()
        assert user_data["email"] == unique_email
        assert user_data["full_name"] == full_name
        assert user_data["is_active"] is True
        assert "id" in user_data
        assert "password" not in user_data
        assert "hashed_password" not in user_data

        # 2. Duplicate email should return 400
        dup_response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": unique_email,
                "password": password
            }
        )
        assert dup_response.status_code == 400

        # 3. Login with invalid password should return 401
        bad_login = await client.post(
            "/api/v1/auth/login/json",
            json={
                "email": unique_email,
                "password": "WrongPassword!"
            }
        )
        assert bad_login.status_code == 401

        # 4. Login via JSON (Frontend style)
        login_json_resp = await client.post(
            "/api/v1/auth/login/json",
            json={
                "email": unique_email,
                "password": password
            }
        )
        assert login_json_resp.status_code == 200
        token_data = login_json_resp.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "bearer"
        token = token_data["access_token"]

        # 5. Login via OAuth2 Form data (Swagger UI style)
        login_form_resp = await client.post(
            "/api/v1/auth/login",
            data={
                "username": unique_email,
                "password": password
            }
        )
        assert login_form_resp.status_code == 200
        assert "access_token" in login_form_resp.json()

        # 6. Access protected route /me without token should return 401
        no_auth_resp = await client.get("/api/v1/auth/me")
        assert no_auth_resp.status_code == 401

        # 7. Access protected route /me with valid Bearer token
        me_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["email"] == unique_email
        assert me_data["id"] == user_data["id"]
        assert me_data["is_active"] is True
