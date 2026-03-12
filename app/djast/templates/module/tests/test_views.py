import pytest
from httpx import ASGITransport, AsyncClient

from main import app


# Example async test using httpx.AsyncClient:
#
# @pytest.mark.asyncio
# async def test_my_endpoint():
#     async with AsyncClient(
#         transport=ASGITransport(app=app), base_url="https://test"
#     ) as client:
#         response = await client.get("/my-endpoint")
#         assert response.status_code == 200
