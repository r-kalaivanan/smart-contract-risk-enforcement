"""
API Authentication Module

Provides API key-based authentication for securing endpoints.
For production use, consider implementing OAuth2/JWT tokens.
"""

import os
import secrets
from typing import Optional
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from datetime import datetime

# API Key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Load API keys from environment variable
# Format: "key1,key2,key3" or single key
VALID_API_KEYS = set(
    os.getenv("SC_GUARD_API_KEYS", "dev-api-key-12345").split(",")
)

# Rate limit configuration (requests per minute)
RATE_LIMIT_PER_MINUTE = int(os.getenv("SC_GUARD_RATE_LIMIT", "10"))


def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    """
    Verify API key from request header.
    
    Args:
        api_key: API key from X-API-Key header
        
    Returns:
        str: Validated API key
        
    Raises:
        HTTPException: If API key is missing or invalid
    """
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Provide X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    if api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
    
    return api_key


def generate_api_key() -> str:
    """
    Generate a secure random API key.
    
    Returns:
        str: Generated API key (32 characters)
    """
    return secrets.token_urlsafe(32)


class APIKeyManager:
    """
    Manage API keys for the service.
    
    In production, this should be backed by a database.
    For now, it's a simple in-memory implementation.
    """
    
    def __init__(self):
        self.keys = {}  # key -> metadata
    
    def create_key(self, name: str, expires_days: Optional[int] = None) -> str:
        """
        Create a new API key.
        
        Args:
            name: Descriptive name for the key
            expires_days: Optional expiration in days
            
        Returns:
            str: Generated API key
        """
        key = generate_api_key()
        self.keys[key] = {
            "name": name,
            "created_at": datetime.utcnow().isoformat(),
            "expires_days": expires_days,
            "usage_count": 0
        }
        return key
    
    def revoke_key(self, key: str) -> bool:
        """
        Revoke an API key.
        
        Args:
            key: API key to revoke
            
        Returns:
            bool: True if key was revoked, False if not found
        """
        if key in self.keys:
            del self.keys[key]
            return True
        return False
    
    def get_key_info(self, key: str) -> Optional[dict]:
        """
        Get metadata for an API key.
        
        Args:
            key: API key to lookup
            
        Returns:
            dict: Key metadata or None if not found
        """
        return self.keys.get(key)
    
    def increment_usage(self, key: str):
        """
        Increment usage counter for a key.
        
        Args:
            key: API key
        """
        if key in self.keys:
            self.keys[key]["usage_count"] += 1


# Global API key manager instance
api_key_manager = APIKeyManager()


# Optional: More secure authentication with JWT tokens
# Uncomment and implement for production use
"""
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
"""
