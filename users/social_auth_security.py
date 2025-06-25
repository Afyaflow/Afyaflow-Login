"""
Secure social authentication utilities for AfyaFlow Auth Service.
Provides proper JWT validation and token security for social providers.
"""

import logging
import requests
import secrets
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
from jose import jwt, jwk, JWTError
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class SocialAuthSecurityError(Exception):
    """Custom exception for social authentication security issues."""
    pass


class GoogleAuthValidator:
    """Secure Google OAuth token validator using JWT validation."""
    
    def __init__(self):
        self.jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
        self.issuer = "https://accounts.google.com"
        self.client_id = settings.GOOGLE_CLIENT_ID
        self.cache_timeout = 3600  # 1 hour
    
    def validate_id_token(self, id_token: str) -> Dict:
        """
        Validate Google ID token using proper JWT validation with Google's public keys.
        
        Args:
            id_token: The Google ID token to validate
            
        Returns:
            Dict containing validated token payload
            
        Raises:
            SocialAuthSecurityError: If token validation fails
        """
        try:
            # Get Google's public keys
            public_keys = self._get_google_public_keys()
            
            # Decode token header to get key ID
            unverified_header = jwt.get_unverified_header(id_token)
            key_id = unverified_header.get('kid')
            
            if not key_id or key_id not in public_keys:
                raise SocialAuthSecurityError("Invalid key ID in token header")
            
            # Get the public key for verification
            public_key = public_keys[key_id]
            
            # Validate the token
            payload = jwt.decode(
                id_token,
                public_key,
                algorithms=['RS256'],
                audience=self.client_id,
                issuer=self.issuer,
                options={
                    'verify_signature': True,
                    'verify_aud': True,
                    'verify_iss': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'require_exp': True,
                    'require_iat': True,
                }
            )
            
            # Additional security checks
            self._validate_token_claims(payload)
            
            logger.info(f"Successfully validated Google ID token for user: {payload.get('email')}")
            return payload
            
        except JWTError as e:
            logger.error(f"JWT validation error for Google ID token: {str(e)}")
            raise SocialAuthSecurityError(f"Invalid Google ID token: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error validating Google ID token: {str(e)}")
            raise SocialAuthSecurityError(f"Token validation failed: {str(e)}")
    
    def validate_access_token(self, access_token: str) -> Dict:
        """
        Validate Google access token by fetching user info.
        This is a fallback method when ID token is not available.
        
        Args:
            access_token: The Google access token
            
        Returns:
            Dict containing user information
            
        Raises:
            SocialAuthSecurityError: If token validation fails
        """
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'User-Agent': 'AfyaFlow-Auth-Service/1.0'
            }
            
            response = requests.get(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                raise SocialAuthSecurityError(
                    f"Failed to validate access token: HTTP {response.status_code}"
                )
            
            user_data = response.json()
            
            # Validate required fields
            if not user_data.get('email') or not user_data.get('email_verified'):
                raise SocialAuthSecurityError("Email not verified by Google")
            
            logger.info(f"Successfully validated Google access token for user: {user_data.get('email')}")
            return user_data
            
        except requests.RequestException as e:
            logger.error(f"Network error validating Google access token: {str(e)}")
            raise SocialAuthSecurityError(f"Network error during token validation: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error validating Google access token: {str(e)}")
            raise SocialAuthSecurityError(f"Access token validation failed: {str(e)}")
    
    def _get_google_public_keys(self) -> Dict[str, str]:
        """
        Fetch and cache Google's public keys for JWT validation.
        
        Returns:
            Dict mapping key IDs to public keys
        """
        cache_key = "google_public_keys"
        public_keys = cache.get(cache_key)
        
        if public_keys is None:
            try:
                response = requests.get(self.jwks_uri, timeout=10)
                response.raise_for_status()
                
                jwks = response.json()
                public_keys = {}
                
                for key_data in jwks.get('keys', []):
                    key_id = key_data.get('kid')
                    if key_id:
                        # Convert JWK to PEM format
                        public_key = jwk.construct(key_data).to_pem()
                        public_keys[key_id] = public_key
                
                # Cache the keys
                cache.set(cache_key, public_keys, self.cache_timeout)
                logger.info(f"Fetched and cached {len(public_keys)} Google public keys")
                
            except Exception as e:
                logger.error(f"Failed to fetch Google public keys: {str(e)}")
                raise SocialAuthSecurityError(f"Failed to fetch public keys: {str(e)}")
        
        return public_keys
    
    def _validate_token_claims(self, payload: Dict) -> None:
        """
        Validate additional security claims in the token payload.
        
        Args:
            payload: The decoded JWT payload
            
        Raises:
            SocialAuthSecurityError: If validation fails
        """
        # Check email verification
        if not payload.get('email_verified', False):
            raise SocialAuthSecurityError("Email not verified by Google")
        
        # Check token age (should not be too old)
        issued_at = payload.get('iat')
        if issued_at:
            token_age = datetime.utcnow().timestamp() - issued_at
            if token_age > 3600:  # 1 hour
                raise SocialAuthSecurityError("Token is too old")
        
        # Check for required claims
        required_claims = ['sub', 'email', 'iss', 'aud', 'exp']
        missing_claims = [claim for claim in required_claims if claim not in payload]
        if missing_claims:
            raise SocialAuthSecurityError(f"Missing required claims: {missing_claims}")


class StateManager:
    """Manage OAuth state parameters for CSRF protection."""
    
    @staticmethod
    def generate_state() -> str:
        """Generate a cryptographically secure state parameter."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_state(session_state: str, received_state: str) -> bool:
        """
        Validate state parameter to prevent CSRF attacks.
        
        Args:
            session_state: State stored in session
            received_state: State received from OAuth provider
            
        Returns:
            True if states match, False otherwise
        """
        if not session_state or not received_state:
            return False
        
        return secrets.compare_digest(session_state, received_state)
    
    @staticmethod
    def store_state(request, state: str) -> None:
        """Store state in session."""
        request.session['oauth_state'] = state
        request.session['oauth_state_timestamp'] = datetime.utcnow().timestamp()
    
    @staticmethod
    def get_and_clear_state(request) -> Optional[str]:
        """Get state from session and clear it."""
        state = request.session.pop('oauth_state', None)
        timestamp = request.session.pop('oauth_state_timestamp', None)
        
        # Check if state is not too old (5 minutes max)
        if timestamp and datetime.utcnow().timestamp() - timestamp > 300:
            logger.warning("OAuth state expired")
            return None
        
        return state


class PKCEManager:
    """Manage PKCE (Proof Key for Code Exchange) for enhanced OAuth security."""
    
    @staticmethod
    def generate_code_verifier() -> str:
        """Generate a code verifier for PKCE."""
        return secrets.token_urlsafe(96)  # 128 characters
    
    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Generate code challenge from verifier using S256 method."""
        import hashlib
        import base64
        
        digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
    
    @staticmethod
    def store_code_verifier(request, code_verifier: str) -> None:
        """Store code verifier in session."""
        request.session['pkce_code_verifier'] = code_verifier
        request.session['pkce_timestamp'] = datetime.utcnow().timestamp()
    
    @staticmethod
    def get_and_clear_code_verifier(request) -> Optional[str]:
        """Get code verifier from session and clear it."""
        code_verifier = request.session.pop('pkce_code_verifier', None)
        timestamp = request.session.pop('pkce_timestamp', None)
        
        # Check if code verifier is not too old (10 minutes max)
        if timestamp and datetime.utcnow().timestamp() - timestamp > 600:
            logger.warning("PKCE code verifier expired")
            return None
        
        return code_verifier


# Global instances
google_auth_validator = GoogleAuthValidator()
state_manager = StateManager()
pkce_manager = PKCEManager()
