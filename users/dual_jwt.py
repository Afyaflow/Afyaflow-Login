"""
Dual JWT manager for backward compatibility during migration.
Supports both legacy client-specific tokens and new gateway-compliant tokens.
"""

import logging
from typing import Dict, Any, Optional, Union, Tuple
from django.utils import timezone
from jose import JWTError

from .models import RegisteredClient, User, OrganizationContext
from .client_jwt import ClientJWTManager
from .gateway_jwt import GatewayJWTManager

logger = logging.getLogger(__name__)


class DualJWTManager:
    """
    Manages both legacy and gateway-compliant JWT tokens during migration period.
    Provides seamless transition between token formats.
    """
    
    def __init__(self, client: RegisteredClient):
        self.client = client
        self.legacy_manager = ClientJWTManager(client)
    
    def create_tokens(self, user: User, organization_context: OrganizationContext = None, 
                     device_fingerprint: str = None) -> Dict[str, Any]:
        """
        Create tokens based on client migration status.
        
        Args:
            user (User): User to create tokens for
            organization_context (OrganizationContext, optional): For provider OCT
            device_fingerprint (str, optional): Device fingerprint for legacy tokens
            
        Returns:
            dict: Token response based on migration status
        """
        migration_status = self.client.migration_status
        
        if migration_status == 'NEW':
            # Only new format tokens
            return self._create_new_format_tokens(user, organization_context)
        
        elif migration_status == 'DUAL':
            # Both legacy and new format tokens
            return self._create_dual_format_tokens(user, organization_context, device_fingerprint)
        
        else:  # LEGACY
            # Only legacy format tokens
            return self._create_legacy_format_tokens(user, device_fingerprint)
    
    def _create_new_format_tokens(self, user: User, organization_context: OrganizationContext = None) -> Dict[str, Any]:
        """Create only gateway-compliant tokens."""
        tokens = GatewayJWTManager.create_token_pair(user, self.client, organization_context)
        
        # Add metadata
        tokens.update({
            'format': 'gateway_compliant',
            'user_type': GatewayJWTManager.get_user_type(user),
            'expires_in': GatewayJWTManager.get_token_lifetime(GatewayJWTManager.get_user_type(user)) * 60,  # seconds
        })
        
        return tokens
    
    def _create_legacy_format_tokens(self, user: User, device_fingerprint: str = None) -> Dict[str, Any]:
        """Create only legacy client-specific tokens."""
        access_token = self.legacy_manager.create_access_token(user)
        refresh_token = self.legacy_manager.create_refresh_token(user, device_fingerprint)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'format': 'legacy',
            'expires_in': self.client.token_lifetime_access * 60,  # seconds
        }
    
    def _create_dual_format_tokens(self, user: User, organization_context: OrganizationContext = None, 
                                  device_fingerprint: str = None) -> Dict[str, Any]:
        """Create both legacy and new format tokens."""
        # Create new format tokens
        new_tokens = self._create_new_format_tokens(user, organization_context)
        
        # Create legacy format tokens
        legacy_tokens = self._create_legacy_format_tokens(user, device_fingerprint)
        
        # Combine both formats
        return {
            # Primary tokens (new format)
            'access_token': new_tokens['access_token'],
            'token_type': 'Bearer',
            'format': 'dual',
            'user_type': new_tokens['user_type'],
            'expires_in': new_tokens['expires_in'],
            
            # OCT if available
            **({} if 'org_context_token' not in new_tokens else {'org_context_token': new_tokens['org_context_token']}),
            
            # Legacy tokens for backward compatibility
            'legacy_access_token': legacy_tokens['access_token'],
            'legacy_refresh_token': legacy_tokens['refresh_token'],
            'legacy_expires_in': legacy_tokens['expires_in'],
        }
    
    def validate_token(self, token: str, token_type: str = 'access') -> Dict[str, Any]:
        """
        Validate token with fallback support for both formats.
        
        Args:
            token (str): Token to validate
            token_type (str): Type of token ('access' or 'org_context')
            
        Returns:
            dict: Validation result with token payload and format info
        """
        validation_result = {
            'valid': False,
            'payload': None,
            'format': None,
            'error': None
        }
        
        # Try new format first if client supports it
        if self.client.supports_new_token_format:
            try:
                if token_type == 'org_context':
                    payload = GatewayJWTManager.validate_organization_context_token(token)
                else:
                    payload = GatewayJWTManager.validate_auth_token(token)
                
                validation_result.update({
                    'valid': True,
                    'payload': payload,
                    'format': 'gateway_compliant'
                })
                
                logger.debug(f"Token validated using new format for client {self.client.client_name}")
                return validation_result
                
            except JWTError as e:
                logger.debug(f"New format validation failed: {str(e)}")
                # Continue to try legacy format
        
        # Try legacy format if client still supports it
        if self.client.migration_status in ['LEGACY', 'DUAL']:
            try:
                if token_type == 'org_context':
                    # Legacy OCT validation
                    payload = self.legacy_manager.validate_organization_context_token(token)
                else:
                    # Legacy access token validation
                    payload = self.legacy_manager.validate_access_token(token)
                
                validation_result.update({
                    'valid': True,
                    'payload': payload,
                    'format': 'legacy'
                })
                
                logger.debug(f"Token validated using legacy format for client {self.client.client_name}")
                return validation_result
                
            except JWTError as e:
                logger.debug(f"Legacy format validation failed: {str(e)}")
                validation_result['error'] = str(e)
        
        # Both formats failed
        validation_result['error'] = 'Token validation failed for all supported formats'
        logger.warning(f"Token validation failed for client {self.client.client_name}")
        
        return validation_result
    
    def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status for this client."""
        return {
            'client_id': str(self.client.client_id),
            'client_name': self.client.client_name,
            'migration_status': self.client.migration_status,
            'supports_new_format': self.client.supports_new_token_format,
            'legacy_support_until': self.client.legacy_token_support_until.isoformat() if self.client.legacy_token_support_until else None,
        }
    
    def update_migration_status(self, new_status: str) -> bool:
        """
        Update client migration status with validation.
        
        Args:
            new_status (str): New migration status ('LEGACY', 'DUAL', 'NEW')
            
        Returns:
            bool: True if update was successful
        """
        valid_transitions = {
            'LEGACY': ['DUAL'],
            'DUAL': ['NEW', 'LEGACY'],  # Allow rollback
            'NEW': ['DUAL']  # Allow rollback if needed
        }
        
        current_status = self.client.migration_status
        
        if new_status in valid_transitions.get(current_status, []):
            self.client.migration_status = new_status
            
            # Update related fields
            if new_status == 'NEW':
                self.client.supports_new_token_format = True
            elif new_status == 'DUAL':
                self.client.supports_new_token_format = True
            # LEGACY keeps existing supports_new_token_format value
            
            self.client.save(update_fields=['migration_status', 'supports_new_token_format'])
            
            logger.info(f"Updated client {self.client.client_name} migration status: {current_status} -> {new_status}")
            return True
        
        logger.warning(f"Invalid migration transition for client {self.client.client_name}: {current_status} -> {new_status}")
        return False
    
    def should_warn_about_deprecation(self) -> bool:
        """Check if client should receive deprecation warnings."""
        if self.client.migration_status == 'LEGACY':
            # Check if legacy support deadline is approaching
            if self.client.legacy_token_support_until:
                days_until_deadline = (self.client.legacy_token_support_until - timezone.now()).days
                return days_until_deadline <= 30  # Warn 30 days before deadline
        
        return False
    
    def get_deprecation_warning(self) -> Optional[str]:
        """Get deprecation warning message if applicable."""
        if self.should_warn_about_deprecation():
            if self.client.legacy_token_support_until:
                deadline = self.client.legacy_token_support_until.strftime('%Y-%m-%d')
                return (
                    f"DEPRECATION WARNING: Legacy token format support for client "
                    f"'{self.client.client_name}' will end on {deadline}. "
                    f"Please migrate to the new gateway-compliant token format."
                )
            else:
                return (
                    f"DEPRECATION WARNING: Legacy token format support for client "
                    f"'{self.client.client_name}' is deprecated. "
                    f"Please migrate to the new gateway-compliant token format."
                )
        
        return None


class MigrationMonitor:
    """Monitor and report on overall migration progress."""
    
    @staticmethod
    def get_migration_progress() -> Dict[str, Any]:
        """Get overall migration progress across all clients."""
        from .models import RegisteredClient
        
        total_clients = RegisteredClient.objects.filter(is_active=True).count()
        
        if total_clients == 0:
            return {
                'total_clients': 0,
                'migration_complete': True,
                'progress_percentage': 100
            }
        
        status_counts = {
            'LEGACY': RegisteredClient.objects.filter(migration_status='LEGACY', is_active=True).count(),
            'DUAL': RegisteredClient.objects.filter(migration_status='DUAL', is_active=True).count(),
            'NEW': RegisteredClient.objects.filter(migration_status='NEW', is_active=True).count(),
        }
        
        progress_percentage = (status_counts['NEW'] / total_clients) * 100
        
        return {
            'total_clients': total_clients,
            'status_counts': status_counts,
            'progress_percentage': round(progress_percentage, 2),
            'migration_complete': status_counts['LEGACY'] == 0 and status_counts['DUAL'] == 0,
            'clients_needing_migration': status_counts['LEGACY'] + status_counts['DUAL']
        }
