import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
from django.conf import settings
from django.utils import timezone
from jose import jwt, JWTError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .models import RegisteredClient, User, BlacklistedToken

logger = logging.getLogger(__name__)


class ClientJWTManager:
    """
    Manages JWT token creation and validation with client-specific signing keys.
    """
    
    def __init__(self, client: RegisteredClient):
        self.client = client
    
    def create_access_token(self, user: User, additional_claims: Dict[str, Any] = None) -> str:
        """
        Create an access token for a user using client-specific signing key.
        
        Args:
            user (User): The user to create token for
            additional_claims (dict, optional): Additional claims to include
            
        Returns:
            str: JWT access token
        """
        now = timezone.now()
        
        # Get token lifetime from client configuration
        lifetime_minutes = self.client.token_lifetime_access
        expires_at = now + timedelta(minutes=lifetime_minutes)
        
        # Base payload
        payload = {
            'sub': str(user.id),
            'email': user.email,
            'iat': int(now.timestamp()),
            'exp': int(expires_at.timestamp()),
            'jti': str(uuid.uuid4()),
            'token_type': 'access',
            'client_id': str(self.client.client_id),
            'client_type': self.client.client_type,
        }
        
        # Add user role information
        if user.primary_role:
            payload['role'] = user.primary_role.name
            payload['permissions'] = user.primary_role.permissions
        
        # Add additional claims
        if additional_claims:
            payload.update(additional_claims)
        
        # Sign token with client-specific key
        token = jwt.encode(
            payload,
            self.client.signing_key,
            algorithm='RS256'
        )
        
        logger.info(f"Created access token for user {user.email} (client: {self.client.client_name})")
        
        return token
    
    def create_refresh_token(self, user: User, device_fingerprint: str = None) -> str:
        """
        Create a refresh token for a user using client-specific signing key.
        
        Args:
            user (User): The user to create token for
            device_fingerprint (str, optional): Device fingerprint for security
            
        Returns:
            str: JWT refresh token
        """
        now = timezone.now()
        
        # Get token lifetime from client configuration
        lifetime_minutes = self.client.token_lifetime_refresh
        expires_at = now + timedelta(minutes=lifetime_minutes)
        
        # Base payload
        payload = {
            'sub': str(user.id),
            'email': user.email,
            'iat': int(now.timestamp()),
            'exp': int(expires_at.timestamp()),
            'jti': str(uuid.uuid4()),
            'token_type': 'refresh',
            'client_id': str(self.client.client_id),
            'client_type': self.client.client_type,
        }
        
        # Add device fingerprint if provided
        if device_fingerprint:
            payload['device_fingerprint'] = device_fingerprint
        
        # Sign token with client-specific key
        token = jwt.encode(
            payload,
            self.client.signing_key,
            algorithm='RS256'
        )
        
        logger.info(f"Created refresh token for user {user.email} (client: {self.client.client_name})")
        
        return token
    
    def validate_token(self, token: str, token_type: str = None) -> Dict[str, Any]:
        """
        Validate a JWT token using client-specific signing key.
        
        Args:
            token (str): JWT token to validate
            token_type (str, optional): Expected token type ('access' or 'refresh')
            
        Returns:
            Dict with validation results and payload
        """
        try:
            # Get public key for verification
            public_key = self._get_public_key()
            
            # Decode token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=['RS256']
            )
            
            # Validate client ID
            token_client_id = payload.get('client_id')
            if token_client_id != str(self.client.client_id):
                return {
                    'valid': False,
                    'reason': 'Token client ID mismatch',
                    'payload': None
                }
            
            # Validate token type if specified
            if token_type and payload.get('token_type') != token_type:
                return {
                    'valid': False,
                    'reason': f'Expected {token_type} token, got {payload.get("token_type")}',
                    'payload': None
                }
            
            # Check if token is blacklisted
            token_jti = payload.get('jti')
            if token_jti and BlacklistedToken.objects.filter(token_jti=token_jti).exists():
                return {
                    'valid': False,
                    'reason': 'Token has been revoked',
                    'payload': None
                }
            
            # Check expiration
            exp = payload.get('exp')
            if exp and datetime.fromtimestamp(exp) < datetime.utcnow():
                return {
                    'valid': False,
                    'reason': 'Token has expired',
                    'payload': None
                }
            
            return {
                'valid': True,
                'reason': 'Token is valid',
                'payload': payload
            }
            
        except JWTError as e:
            logger.warning(f"JWT validation failed for client {self.client.client_name}: {e}")
            return {
                'valid': False,
                'reason': f'JWT validation error: {str(e)}',
                'payload': None
            }
        except Exception as e:
            logger.error(f"Unexpected error validating JWT for client {self.client.client_name}: {e}")
            return {
                'valid': False,
                'reason': f'Validation error: {str(e)}',
                'payload': None
            }
    
    def _get_public_key(self) -> str:
        """
        Get the public key for token verification.
        
        Returns:
            str: PEM-encoded public key
        """
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                self.client.signing_key.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize to PEM format
            pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem_public_key.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to extract public key for client {self.client.client_name}: {e}")
            raise
    
    def blacklist_token(self, token: str, reason: str = "Manual revocation") -> bool:
        """
        Blacklist a JWT token.
        
        Args:
            token (str): JWT token to blacklist
            reason (str): Reason for blacklisting
            
        Returns:
            bool: True if successfully blacklisted
        """
        try:
            # Decode token to get JTI and user info
            validation_result = self.validate_token(token)
            
            if not validation_result['valid']:
                logger.warning(f"Attempted to blacklist invalid token: {validation_result['reason']}")
                return False
            
            payload = validation_result['payload']
            jti = payload.get('jti')
            user_id = payload.get('sub')
            exp = payload.get('exp')
            
            if not jti:
                logger.error("Cannot blacklist token without JTI")
                return False
            
            # Get user
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                logger.error(f"User {user_id} not found for token blacklisting")
                return False
            
            # Create blacklist entry
            BlacklistedToken.objects.create(
                token_jti=jti,
                user=user,
                reason=reason,
                expires_at=datetime.fromtimestamp(exp) if exp else timezone.now() + timedelta(days=1),
                client=self.client,
                client_type=self.client.client_type,
                violation_reason=reason
            )
            
            logger.info(f"Blacklisted token {jti} for user {user.email} (client: {self.client.client_name})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e}")
            return False


class ClientJWTAuthenticationBackend:
    """
    Authentication backend that supports client-specific JWT validation.
    """
    
    @staticmethod
    def authenticate_token(token: str, client: RegisteredClient) -> Optional[Dict[str, Any]]:
        """
        Authenticate a JWT token for a specific client.
        
        Args:
            token (str): JWT token to authenticate
            client (RegisteredClient): Client to validate against
            
        Returns:
            Dict with authentication results or None
        """
        jwt_manager = ClientJWTManager(client)
        validation_result = jwt_manager.validate_token(token)
        
        if not validation_result['valid']:
            logger.warning(f"Token authentication failed: {validation_result['reason']}")
            return None
        
        payload = validation_result['payload']
        user_id = payload.get('sub')
        
        try:
            user = User.objects.get(id=user_id)
            
            return {
                'user': user,
                'payload': payload,
                'client': client
            }
            
        except User.DoesNotExist:
            logger.error(f"User {user_id} not found during token authentication")
            return None
    
    @staticmethod
    def create_token_pair(user: User, client: RegisteredClient, device_fingerprint: str = None) -> Dict[str, str]:
        """
        Create access and refresh token pair for a user and client.
        
        Args:
            user (User): User to create tokens for
            client (RegisteredClient): Client to create tokens for
            device_fingerprint (str, optional): Device fingerprint
            
        Returns:
            Dict containing access_token and refresh_token
        """
        jwt_manager = ClientJWTManager(client)
        
        access_token = jwt_manager.create_access_token(user)
        refresh_token = jwt_manager.create_refresh_token(user, device_fingerprint)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': client.token_lifetime_access * 60,  # Convert to seconds
            'client_id': str(client.client_id)
        }


def get_jwt_manager_for_client(client_id: str) -> Optional[ClientJWTManager]:
    """
    Get JWT manager for a specific client.
    
    Args:
        client_id (str): Client ID
        
    Returns:
        ClientJWTManager or None
    """
    try:
        client = RegisteredClient.objects.get(client_id=client_id, is_active=True)
        return ClientJWTManager(client)
    except RegisteredClient.DoesNotExist:
        logger.error(f"Client {client_id} not found")
        return None


def validate_token_for_client(token: str, client_id: str) -> Dict[str, Any]:
    """
    Validate a token for a specific client.
    
    Args:
        token (str): JWT token
        client_id (str): Client ID
        
    Returns:
        Dict with validation results
    """
    jwt_manager = get_jwt_manager_for_client(client_id)
    
    if not jwt_manager:
        return {
            'valid': False,
            'reason': 'Client not found',
            'payload': None
        }
    
    return jwt_manager.validate_token(token)
