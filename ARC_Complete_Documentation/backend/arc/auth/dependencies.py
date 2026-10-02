from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
import os

API_KEY_NAME = "X-ARC-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# In a real environment, this would be fetched from a secure store or DB
VALID_API_KEYS = set(os.getenv("ARC_VALID_API_KEYS", "dev-test-key").split(","))

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header in VALID_API_KEYS:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )
