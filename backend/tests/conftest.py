import pytest
import httpx
from app.main import app
from app.core.database import engine

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest.fixture(autouse=True)
async def cleanup_engine():
    yield
    await engine.dispose()
