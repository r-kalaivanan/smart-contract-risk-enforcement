"""
Rate Limiting Module

Implements rate limiting to prevent API abuse and ensure fair usage.
Uses slowapi library for in-memory rate limiting.
"""

import os
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from typing import Callable


# Rate limit configuration
DEFAULT_RATE_LIMIT = os.getenv("SC_GUARD_RATE_LIMIT", "10/minute")
BURST_RATE_LIMIT = os.getenv("SC_GUARD_BURST_LIMIT", "30/hour")


def get_api_key_identifier(request: Request) -> str:
    """
    Get identifier for rate limiting.
    
    Uses API key if present, otherwise falls back to IP address.
    This allows authenticated users to have their own rate limit buckets.
    
    Args:
        request: FastAPI request object
        
    Returns:
        str: Identifier for rate limiting
    """
    api_key = request.headers.get("X-API-Key")
    if api_key:
        # Use first 8 chars of API key as identifier
        return f"apikey:{api_key[:8]}"
    else:
        # Fall back to IP address for unauthenticated requests
        return f"ip:{get_remote_address(request)}"


# Initialize rate limiter
limiter = Limiter(
    key_func=get_api_key_identifier,
    default_limits=[DEFAULT_RATE_LIMIT],
    storage_uri="memory://",
    # Optionally use Redis for distributed rate limiting:
    # storage_uri=os.getenv("REDIS_URL", "redis://localhost:6379"),
)


def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> dict:
    """
    Custom handler for rate limit exceeded errors.
    
    Args:
        request: FastAPI request object
        exc: RateLimitExceeded exception
        
    Returns:
        dict: Error response
    """
    return {
        "detail": f"Rate limit exceeded: {exc.detail}",
        "retry_after": 60,  # Seconds
        "limit": str(exc.detail)
    }


# Rate limit tiers (for future implementation)
RATE_LIMIT_TIERS = {
    "free": "10/minute",
    "basic": "60/minute",
    "premium": "300/minute",
    "enterprise": "1000/minute"
}


def get_rate_limit_for_key(api_key: str) -> str:
    """
    Get rate limit for a specific API key.
    
    In production, this would query a database to determine
    the user's subscription tier.
    
    Args:
        api_key: API key
        
    Returns:
        str: Rate limit string (e.g., "60/minute")
    """
    # For now, return default
    # TODO: Implement tier-based rate limiting
    return DEFAULT_RATE_LIMIT


class CustomLimiter:
    """
    Custom rate limiter with additional features.
    
    Provides more granular control over rate limiting,
    including burst limits and tier-based limits.
    """
    
    def __init__(self, base_limiter: Limiter):
        self.limiter = base_limiter
    
    def limit(self, limit_value: str):
        """
        Decorator for rate limiting endpoints.
        
        Args:
            limit_value: Rate limit string (e.g., "10/minute")
            
        Returns:
            Decorator function
        """
        return self.limiter.limit(limit_value)
    
    def shared_limit(self, limit_value: str, scope: str):
        """
        Decorator for shared rate limiting across multiple endpoints.
        
        Args:
            limit_value: Rate limit string
            scope: Scope identifier for sharing limits
            
        Returns:
            Decorator function
        """
        return self.limiter.shared_limit(limit_value, scope=scope)


# Example usage in endpoints:
"""
@app.post("/api/v1/scan")
@limiter.limit("10/minute")
async def scan_contract(request: Request, ...):
    # Endpoint implementation
    pass
"""

# For burst protection on expensive operations:
"""
@app.post("/api/v1/batch-scan")
@limiter.limit("5/minute")  # Lower limit for resource-intensive operations
async def batch_scan(request: Request, ...):
    # Endpoint implementation
    pass
"""
