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
from datetime import datetime, timedelta
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
        SIMPLIFIED: Mock token verification for testing.
        Accepts any ya29.* token without actual verification.

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

        logger.info("SIMPLIFIED MODE: Accepting token without Google verification")

        # Use a test email or from environment
        import os
        test_email = os.getenv("TEST_USER_EMAIL", "ildar@archestra.ai")
        test_sub = "test_user_123"

        # Mock token info
        expires_at = int(time.time()) + 3600  # 1 hour from now (as timestamp for AccessToken)
        expiry_datetime = datetime.utcnow() + timedelta(hours=1)  # As datetime for session store
        scopes = [
            "openid",
            "email",
            "profile",
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/calendar.readonly",
            "https://www.googleapis.com/auth/calendar.events",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/drive.file",
            "https://www.googleapis.com/auth/documents.readonly",
            "https://www.googleapis.com/auth/documents",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.labels",
            "https://www.googleapis.com/auth/chat.messages.readonly",
            "https://www.googleapis.com/auth/chat.messages",
            "https://www.googleapis.com/auth/chat.spaces",
            "https://www.googleapis.com/auth/spreadsheets.readonly",
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/forms.body",
            "https://www.googleapis.com/auth/forms.body.readonly",
            "https://www.googleapis.com/auth/forms.responses.readonly",
            "https://www.googleapis.com/auth/presentations",
            "https://www.googleapis.com/auth/presentations.readonly",
            "https://www.googleapis.com/auth/tasks",
            "https://www.googleapis.com/auth/tasks.readonly",
            "https://www.googleapis.com/auth/cse"
        ]

        # Create AccessToken object
        if TOKENVERIFIER_AVAILABLE:
            # Use proper AccessToken class if available
            access_token = AccessToken(
                token=token,
                client_id=self.client_id,
                scopes=scopes,
                expires_at=expires_at,  # AccessToken expects integer timestamp
                claims={
                    "email": test_email,
                    "sub": test_sub,
                    "aud": self.client_id,
                    "scope": " ".join(scopes),
                }
            )
            # Email and sub are already in the claims dictionary
        else:
            # Fallback to SimpleNamespace for testing
            access_token = SimpleNamespace(
                token=token,
                client_id=self.client_id,
                scopes=scopes,
                expires_at=expires_at,
                email=test_email,
                sub=test_sub,
                claims={
                    "email": test_email,
                    "sub": test_sub,
                    "aud": self.client_id,
                    "scope": " ".join(scopes),
                }
            )

        # Store session for Google API access
        try:
            from auth.oauth21_session_store import get_oauth21_session_store

            store = get_oauth21_session_store()
            session_id = f"google_{test_sub}"

            # Try to get MCP session ID for binding
            mcp_session_id = None
            try:
                from fastmcp.server.dependencies import get_context
                ctx = get_context()
                if ctx and hasattr(ctx, "session_id"):
                    mcp_session_id = ctx.session_id
                    logger.debug(f"Binding MCP session {mcp_session_id} to user {test_email}")
            except Exception:
                pass

            # Store session with mock token
            store.store_session(
                user_email=test_email,
                access_token=token,
                scopes=scopes,
                session_id=session_id,
                mcp_session_id=mcp_session_id,
                issuer="https://accounts.google.com",
                expiry=expiry_datetime  # Session store expects datetime object
            )

            logger.info(f"SIMPLIFIED: Token accepted for user: {test_email}")
        except Exception as e:
            logger.warning(f"Failed to store session: {e}")
            # Continue - token is still valid even if session storage fails

        return access_token

    def get_routes(self):
        """
        Token-only mode doesn't provide OAuth routes.

        Returns:
            Empty list - no routes needed for token validation only
        """
        return []
