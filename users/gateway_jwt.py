"""
Gateway-compliant JWT token generation and validation.
Implements user-type-specific tokens as per Afyaflow GraphQL Gateway specification.
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union, Tuple
from django.conf import settings
from django.utils import timezone
from jose import jwt, JWTError

from .models import RegisteredClient, User, BlacklistedToken, OrganizationContext

logger = logging.getLogger(__name__)


class GatewayJWTManager:
    """
    Manages JWT token creation and validation according to Afyaflow GraphQL Gateway specification.
    Supports user-type-specific tokens with dedicated signing secrets.
    """
    
    @staticmethod
    def get_user_type(user: User) -> str:
        """Determine user type based on roles."""
        if user.is_operations_user():
            return 'operations'
        elif user.is_provider():
            return 'provider'
        elif user.is_patient():
            return 'patient'
        else:
            # Default fallback
            return 'patient'
    
    @staticmethod
    def get_signing_secret(user_type: str) -> str:
        """Get the appropriate signing secret for user type."""
        secret_map = {
            'provider': settings.PROVIDER_AUTH_TOKEN_SECRET,
            'patient': settings.PATIENT_AUTH_TOKEN_SECRET,
            'operations': settings.OPERATIONS_AUTH_TOKEN_SECRET,
        }
        
        secret = secret_map.get(user_type)
        if not secret:
            logger.error(f"No signing secret found for user type: {user_type}")
            raise ValueError(f"No signing secret configured for user type: {user_type}")
        
        return secret
    
    @staticmethod
    def get_token_lifetime(user_type: str) -> int:
        """Get token lifetime in minutes for user type."""
        lifetime_map = {
            'provider': settings.PROVIDER_TOKEN_LIFETIME,
            'patient': settings.PATIENT_TOKEN_LIFETIME,
            'operations': settings.OPERATIONS_TOKEN_LIFETIME,
        }
        
        return lifetime_map.get(user_type, 60)  # Default 60 minutes
    
    @classmethod
    def create_auth_token(cls, user: User, client: RegisteredClient = None) -> str:
        """
        Create a gateway-compliant Auth Token (AT) for a user.
        
        Args:
            user (User): The user to create token for
            client (RegisteredClient, optional): Client information for backward compatibility
            
        Returns:
            str: JWT auth token
        """
        now = timezone.now()
        user_type = cls.get_user_type(user)
        
        # Get user-type-specific configuration
        signing_secret = cls.get_signing_secret(user_type)
        lifetime_minutes = cls.get_token_lifetime(user_type)
        expires_at = now + timedelta(minutes=lifetime_minutes)
        
        # Base payload structure per gateway specification
        payload = {
            'sub': str(user.id),
            'email': user.email,
            'isActive': user.is_active,
            'name': f"{user.first_name} {user.last_name}".strip(),
            'user_type': user_type,
            'iat': int(now.timestamp()),
            'exp': int(expires_at.timestamp()),
            'jti': str(uuid.uuid4()),
        }
        
        # Add user-type-specific claims
        if user_type == 'operations':
            # Operations users get roles and permissions
            roles = [assignment.role.name for assignment in user.role_assignments.filter(is_active=True)]
            permissions = []
            for assignment in user.role_assignments.filter(is_active=True):
                permissions.extend(assignment.role.permissions)
            
            payload.update({
                'roles': roles,
                'permissions': list(set(permissions))  # Remove duplicates
            })
        
        # Add client information for backward compatibility
        if client:
            payload.update({
                'client_id': str(client.client_id),
                'client_type': client.client_type,
            })
        
        # Sign token with user-type-specific secret
        token = jwt.encode(
            payload,
            signing_secret,
            algorithm='HS256'  # Using HMAC for gateway compliance
        )
        
        logger.info(f"Created {user_type} auth token for user {user.email}")
        
        return token
    
    @classmethod
    def create_organization_context_token(cls, user: User, organization_context: OrganizationContext) -> str:
        """
        Create an Organization Context Token (OCT) for a provider.
        
        Args:
            user (User): The provider user
            organization_context (OrganizationContext): Organization context information
            
        Returns:
            str: JWT organization context token
        """
        if not user.is_provider():
            raise ValueError("Organization Context Tokens can only be created for providers")
        
        now = timezone.now()
        lifetime_minutes = settings.OCT_TOKEN_LIFETIME
        expires_at = now + timedelta(minutes=lifetime_minutes)
        
        # OCT payload structure per gateway specification
        payload = {
            'sub': str(user.id),
            'orgId': str(organization_context.organization_id),
            'iat': int(now.timestamp()),
            'exp': int(expires_at.timestamp()),
        }
        
        # Add hierarchical organization structure
        if organization_context.branch_id:
            payload['branchId'] = str(organization_context.branch_id)
        if organization_context.cluster_id:
            payload['clusterId'] = str(organization_context.cluster_id)
        
        # Add organization-specific permissions and services
        payload.update({
            'permissions': organization_context.organization_permissions,
            'subscribedServices': organization_context.subscribed_services
        })
        
        # Sign with dedicated OCT secret
        token = jwt.encode(
            payload,
            settings.ORG_CONTEXT_TOKEN_SECRET,
            algorithm='HS256'
        )
        
        logger.info(f"Created OCT for user {user.email} in organization {organization_context.organization_id}")
        
        return token
    
    @classmethod
    def validate_auth_token(cls, token: str, expected_user_type: str = None) -> Dict[str, Any]:
        """
        Validate a gateway-compliant auth token.
        
        Args:
            token (str): JWT token to validate
            expected_user_type (str, optional): Expected user type for validation
            
        Returns:
            dict: Decoded token payload
            
        Raises:
            JWTError: If token is invalid
        """
        # First, try to decode without verification to get user_type
        try:
            unverified_payload = jwt.get_unverified_claims(token)
            user_type = unverified_payload.get('user_type')
            
            if not user_type:
                raise JWTError("Token missing user_type claim")
            
            if expected_user_type and user_type != expected_user_type:
                raise JWTError(f"Expected user_type {expected_user_type}, got {user_type}")
            
            # Get appropriate signing secret
            signing_secret = cls.get_signing_secret(user_type)
            
            # Validate token with correct secret
            payload = jwt.decode(
                token,
                signing_secret,
                algorithms=['HS256']
            )
            
            # Check if token is blacklisted
            jti = payload.get('jti')
            if jti and BlacklistedToken.objects.filter(token_jti=jti).exists():
                raise JWTError("Token has been blacklisted")
            
            logger.debug(f"Successfully validated {user_type} auth token")
            
            return payload
            
        except JWTError as e:
            logger.warning(f"Token validation failed: {str(e)}")
            raise
    
    @classmethod
    def validate_organization_context_token(cls, token: str) -> Dict[str, Any]:
        """
        Validate an Organization Context Token (OCT).
        
        Args:
            token (str): OCT token to validate
            
        Returns:
            dict: Decoded token payload
            
        Raises:
            JWTError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                settings.ORG_CONTEXT_TOKEN_SECRET,
                algorithms=['HS256']
            )
            
            logger.debug(f"Successfully validated OCT for organization {payload.get('orgId')}")
            
            return payload
            
        except JWTError as e:
            logger.warning(f"OCT validation failed: {str(e)}")
            raise
    
    @classmethod
    def create_token_pair(cls, user: User, client: RegisteredClient = None, 
                         organization_context: OrganizationContext = None) -> Dict[str, str]:
        """
        Create a complete token pair for a user.
        
        Args:
            user (User): The user to create tokens for
            client (RegisteredClient, optional): Client information
            organization_context (OrganizationContext, optional): For providers requiring OCT
            
        Returns:
            dict: Token pair with access_token and optionally org_context_token
        """
        tokens = {
            'access_token': cls.create_auth_token(user, client),
            'token_type': 'Bearer'
        }
        
        # Add OCT for providers if organization context is provided
        if user.is_provider() and organization_context:
            tokens['org_context_token'] = cls.create_organization_context_token(user, organization_context)
        
        return tokens
    
    @classmethod
    def blacklist_token(cls, token: str, user: User = None, reason: str = "Manual blacklist") -> bool:
        """
        Blacklist a token by adding its JTI to the blacklist.

        Args:
            token (str): Token to blacklist
            user (User, optional): User who owned the token
            reason (str): Reason for blacklisting

        Returns:
            bool: True if successfully blacklisted
        """
        try:
            # Decode without verification to get JTI and user info
            unverified_payload = jwt.get_unverified_claims(token)
            jti = unverified_payload.get('jti')
            exp = unverified_payload.get('exp')

            if jti:
                # Get user if not provided
                if not user:
                    user_id = unverified_payload.get('sub')
                    if user_id:
                        try:
                            user = User.objects.get(id=user_id)
                        except User.DoesNotExist:
                            logger.warning(f"User {user_id} not found for token blacklisting")

                # Convert exp timestamp to datetime
                expires_at = timezone.datetime.fromtimestamp(exp, tz=timezone.get_current_timezone()) if exp else timezone.now() + timedelta(hours=1)

                BlacklistedToken.objects.get_or_create(
                    token_jti=jti,
                    defaults={
                        'user': user,
                        'reason': reason,
                        'expires_at': expires_at,
                        'blacklisted_at': timezone.now()
                    }
                )
                logger.info(f"Blacklisted token with JTI: {jti}")
                return True

        except Exception as e:
            logger.error(f"Failed to blacklist token: {str(e)}")

        return False
