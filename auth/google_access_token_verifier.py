"""
Google Access Token Verifier for token-only authentication mode.

This module implements a simple TokenVerifier that validates Google access tokens
without handling OAuth flows. It's designed to work with external IDP brokers
that provide Google access tokens directly to clients.

Usage:
    Set MCP_TOKEN_ONLY_MODE=true to enable this verifier instead of the full
    OAuth 2.1 RemoteAuthProvider.
"""

import logging
import time
from typing import Optional
from types import SimpleNamespace
import ssl
import certifi

import aiohttp

try:
    from fastmcp.server.auth import AccessToken, TokenVerifier
    TOKENVERIFIER_AVAILABLE = True
except ImportError:
    TOKENVERIFIER_AVAILABLE = False
    TokenVerifier = object  # Fallback for type hints
    AccessToken = object

logger = logging.getLogger(__name__)


class GoogleAccessTokenVerifier(TokenVerifier):
    """
    TokenVerifier that validates Google OAuth access tokens.
    
    This verifier:
    - Only validates tokens (doesn't handle OAuth flows)
    - Verifies tokens using Google's tokeninfo endpoint
    - Stores sessions for Google API access
    - Works with external IDP brokers that provide Google tokens
    """
    
    def __init__(self, client_id: str, resource_server_url: Optional[str] = None):
        """
        Initialize the Google Access Token Verifier.
        
        Args:
            client_id: Google OAuth client ID for audience validation
            resource_server_url: Optional URL of this resource server
        """
        if not TOKENVERIFIER_AVAILABLE:
            raise ImportError("FastMCP required for TokenVerifier")
        
        # Initialize parent TokenVerifier
        super().__init__(resource_server_url=resource_server_url)
        
        self.client_id = client_id
        
        if not self.client_id:
            logger.error("GOOGLE_OAUTH_CLIENT_ID not set - Token verification will not work")
            raise ValueError("GOOGLE_OAUTH_CLIENT_ID is required for token verification")
        
        logger.info(f"Initialized GoogleAccessTokenVerifier with client_id: {client_id[:10]}...")
    
    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """
        Verify a Google access token and return AccessToken if valid.
        
        Args:
            token: The bearer token to verify (should be a Google access token)
            
        Returns:
            AccessToken if valid, None otherwise
        """
        if not token:
            logger.debug("No token provided")
            return None
        
        # Only handle Google OAuth access tokens (ya29.*)
        if not token.startswith("ya29."):
            logger.debug(f"Token does not appear to be a Google access token (doesn't start with ya29.)")
            return None
        
        logger.debug("Verifying Google OAuth access token")
        
        try:
            # Create SSL context with proper certificates
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
                # Verify token using Google's tokeninfo endpoint
                url = f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"
                
                async with session.get(url) as response:
                    if response.status != 200:
                        logger.error(f"Token verification failed: HTTP {response.status}")
                        return None
                    
                    token_info = await response.json()
                    
                    # Verify the token is for our client
                    aud = token_info.get("aud")
                    if aud != self.client_id:
                        logger.error(
                            f"Token audience mismatch: expected {self.client_id}, got {aud}"
                        )
                        return None
                    
                    # Check if token is expired
                    expires_in = int(token_info.get("expires_in", 0))
                    if expires_in <= 0:
                        logger.error("Token is expired")
                        return None
                    
                    # Calculate expiration timestamp
                    expires_at = int(time.time()) + expires_in
                    
                    # Extract user information
                    user_email = token_info.get("email", "")
                    user_sub = token_info.get("sub", "")
                    scopes = token_info.get("scope", "").split()
                    
                    # Create AccessToken object
                    if TOKENVERIFIER_AVAILABLE:
                        # Use proper AccessToken class if available
                        access_token = AccessToken(
                            token=token,
                            client_id=self.client_id,
                            scopes=scopes,
                            expires_at=expires_at,
                            claims={
                                "email": user_email,
                                "sub": user_sub,
                                "aud": aud,
                                "scope": token_info.get("scope", ""),
                            }
                        )
                        # Add email and sub as direct attributes for compatibility
                        access_token.email = user_email
                        access_token.sub = user_sub
                    else:
                        # Fallback to SimpleNamespace for testing
                        access_token = SimpleNamespace(
                            token=token,
                            client_id=self.client_id,
                            scopes=scopes,
                            expires_at=expires_at,
                            email=user_email,
                            sub=user_sub,
                            claims={
                                "email": user_email,
                                "sub": user_sub,
                                "aud": aud,
                                "scope": token_info.get("scope", ""),
                            }
                        )
                    
                    # Store session for Google API access
                    if user_email:
                        try:
                            from auth.oauth21_session_store import get_oauth21_session_store
                            
                            store = get_oauth21_session_store()
                            session_id = f"google_{user_sub or 'unknown'}"
                            
                            # Try to get MCP session ID for binding
                            mcp_session_id = None
                            try:
                                from fastmcp.server.dependencies import get_context
                                ctx = get_context()
                                if ctx and hasattr(ctx, "session_id"):
                                    mcp_session_id = ctx.session_id
                                    logger.debug(f"Binding MCP session {mcp_session_id} to user {user_email}")
                            except Exception:
                                pass
                            
                            # Store session with Google as issuer
                            store.store_session(
                                user_email=user_email,
                                access_token=token,
                                scopes=scopes,
                                session_id=session_id,
                                mcp_session_id=mcp_session_id,
                                issuer="https://accounts.google.com",
                                expiry=expires_at
                            )
                            
                            logger.info(f"Successfully verified token for {user_email}")
                        except Exception as e:
                            logger.warning(f"Failed to store session: {e}")
                            # Continue - token is still valid even if session storage fails
                    
                    return access_token
                    
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error verifying token: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error verifying token: {e}")
            return None
    
    def get_routes(self):
        """
        Token-only mode doesn't provide OAuth routes.
        
        Returns:
            Empty list - no routes needed for token validation only
        """
        return []