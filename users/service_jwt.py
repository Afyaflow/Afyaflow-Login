"""
Service Account JWT manager for inter-service authentication.
Implements service-to-service authentication with Service Account IDs.
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from django.conf import settings
from django.utils import timezone
from jose import jwt, JWTError

from .models import ServiceAccount

logger = logging.getLogger(__name__)


class ServiceJWTManager:
    """
    Manages JWT tokens for service-to-service authentication.
    Provides secure inter-service communication with permission-based access control.
    """
    
    # Service token lifetime (shorter for security)
    SERVICE_TOKEN_LIFETIME_MINUTES = 15
    
    @staticmethod
    def get_service_signing_secret() -> str:
        """Get the signing secret for service tokens."""
        # Use a dedicated service secret or fall back to operations secret
        secret = getattr(settings, 'SERVICE_AUTH_TOKEN_SECRET', None)
        if not secret:
            secret = getattr(settings, 'OPERATIONS_AUTH_TOKEN_SECRET', None)
        
        if not secret:
            raise ValueError("No service authentication secret configured")
        
        return secret
    
    @classmethod
    def create_service_token(cls, service_account: ServiceAccount, target_service: str = None, 
                           additional_claims: Dict[str, Any] = None) -> str:
        """
        Create a service authentication token.
        
        Args:
            service_account (ServiceAccount): The service account requesting the token
            target_service (str, optional): Target service for scoped access
            additional_claims (dict, optional): Additional claims to include
            
        Returns:
            str: JWT service token
        """
        if not service_account.is_active:
            raise ValueError(f"Service account {service_account.service_id} is not active")
        
        now = timezone.now()
        expires_at = now + timedelta(minutes=cls.SERVICE_TOKEN_LIFETIME_MINUTES)
        
        # Base payload for service tokens
        payload = {
            'sub': service_account.service_id,
            'service_type': service_account.service_type,
            'permissions': service_account.permissions,
            'iat': int(now.timestamp()),
            'exp': int(expires_at.timestamp()),
            'jti': str(uuid.uuid4()),
            'token_type': 'service',
        }
        
        # Add target service for scoped access
        if target_service:
            payload['target_service'] = target_service
            
            # Filter permissions relevant to target service
            relevant_permissions = [
                perm for perm in service_account.permissions 
                if perm.startswith(f'{target_service}:') or ':' not in perm
            ]
            payload['scoped_permissions'] = relevant_permissions
        
        # Add additional claims
        if additional_claims:
            payload.update(additional_claims)
        
        # Sign token with service secret
        signing_secret = cls.get_service_signing_secret()
        token = jwt.encode(
            payload,
            signing_secret,
            algorithm='HS256'
        )
        
        logger.info(f"Created service token for {service_account.service_id}")
        if target_service:
            logger.info(f"Token scoped to target service: {target_service}")
        
        return token
    
    @classmethod
    def validate_service_token(cls, token: str, required_service_type: str = None,
                             required_permissions: List[str] = None) -> Dict[str, Any]:
        """
        Validate a service authentication token.
        
        Args:
            token (str): JWT service token to validate
            required_service_type (str, optional): Required service type
            required_permissions (list, optional): Required permissions
            
        Returns:
            dict: Decoded token payload
            
        Raises:
            JWTError: If token is invalid or doesn't meet requirements
        """
        try:
            # Validate token signature and expiration
            signing_secret = cls.get_service_signing_secret()
            payload = jwt.decode(
                token,
                signing_secret,
                algorithms=['HS256']
            )
            
            # Verify token type
            if payload.get('token_type') != 'service':
                raise JWTError("Invalid token type for service authentication")
            
            # Get service account
            service_id = payload.get('sub')
            if not service_id:
                raise JWTError("Token missing service ID")
            
            try:
                service_account = ServiceAccount.objects.get(
                    service_id=service_id,
                    is_active=True
                )
            except ServiceAccount.DoesNotExist:
                raise JWTError(f"Service account {service_id} not found or inactive")
            
            # Verify service type if required
            if required_service_type and service_account.service_type != required_service_type:
                raise JWTError(
                    f"Service type mismatch: expected {required_service_type}, "
                    f"got {service_account.service_type}"
                )
            
            # Verify permissions if required
            if required_permissions:
                # Use scoped permissions if available, otherwise use full permissions
                available_permissions = payload.get('scoped_permissions', payload.get('permissions', []))
                
                missing_permissions = []
                for required_perm in required_permissions:
                    if not cls._has_permission(available_permissions, required_perm):
                        missing_permissions.append(required_perm)
                
                if missing_permissions:
                    raise JWTError(f"Missing required permissions: {missing_permissions}")
            
            # Add service account info to payload
            payload['service_account'] = {
                'id': service_account.id,
                'service_id': service_account.service_id,
                'service_type': service_account.service_type,
                'permissions': service_account.permissions
            }
            
            logger.debug(f"Successfully validated service token for {service_id}")
            
            return payload
            
        except JWTError as e:
            logger.warning(f"Service token validation failed: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error validating service token: {str(e)}")
            raise JWTError(f"Token validation error: {str(e)}")
    
    @staticmethod
    def _has_permission(available_permissions: List[str], required_permission: str) -> bool:
        """
        Check if a required permission is available in the list.
        Supports wildcard permissions (e.g., 'read:*' matches 'read:patients').
        
        Args:
            available_permissions (list): List of available permissions
            required_permission (str): Required permission to check
            
        Returns:
            bool: True if permission is available
        """
        # Direct match
        if required_permission in available_permissions:
            return True
        
        # Check for wildcard permissions
        for available_perm in available_permissions:
            if available_perm.endswith(':*'):
                # Wildcard permission (e.g., 'read:*')
                prefix = available_perm[:-1]  # Remove '*'
                if required_permission.startswith(prefix):
                    return True
            elif '*' in available_perm:
                # Other wildcard patterns could be added here
                continue
        
        return False
    
    @classmethod
    def create_service_to_service_token(cls, source_service_id: str, target_service_id: str,
                                      permissions: List[str] = None) -> str:
        """
        Create a token for service-to-service communication.
        
        Args:
            source_service_id (str): ID of the service making the request
            target_service_id (str): ID of the target service
            permissions (list, optional): Specific permissions for this interaction
            
        Returns:
            str: JWT token for service-to-service communication
        """
        try:
            source_service = ServiceAccount.objects.get(
                service_id=source_service_id,
                is_active=True
            )
        except ServiceAccount.DoesNotExist:
            raise ValueError(f"Source service {source_service_id} not found or inactive")
        
        # Create token with target service scope
        additional_claims = {
            'source_service': source_service_id,
            'target_service': target_service_id,
        }
        
        if permissions:
            additional_claims['requested_permissions'] = permissions
        
        return cls.create_service_token(
            source_service,
            target_service=target_service_id,
            additional_claims=additional_claims
        )
    
    @classmethod
    def get_service_info_from_token(cls, token: str) -> Dict[str, Any]:
        """
        Extract service information from a token without full validation.
        Useful for logging and debugging.
        
        Args:
            token (str): JWT service token
            
        Returns:
            dict: Service information from token
        """
        try:
            # Decode without verification to get claims
            unverified_payload = jwt.get_unverified_claims(token)
            
            return {
                'service_id': unverified_payload.get('sub'),
                'service_type': unverified_payload.get('service_type'),
                'target_service': unverified_payload.get('target_service'),
                'token_type': unverified_payload.get('token_type'),
                'expires_at': unverified_payload.get('exp'),
                'issued_at': unverified_payload.get('iat'),
            }
        except Exception as e:
            logger.warning(f"Failed to extract service info from token: {str(e)}")
            return {}
    
    @classmethod
    def is_service_token(cls, token: str) -> bool:
        """
        Check if a token is a service token without full validation.
        
        Args:
            token (str): JWT token to check
            
        Returns:
            bool: True if token appears to be a service token
        """
        try:
            unverified_payload = jwt.get_unverified_claims(token)
            return unverified_payload.get('token_type') == 'service'
        except Exception:
            return False
