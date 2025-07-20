import logging
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from typing import Dict, Any, Optional

from .models import RegisteredClient, RefreshToken, BlacklistedToken
from .client_utils import ClientCredentialManager, generate_client_credentials
from .authentication import JWTAuthentication

logger = logging.getLogger(__name__)


class CredentialRotationManager:
    """
    Manages secure credential rotation for registered clients.
    """
    
    def __init__(self, client: RegisteredClient):
        self.client = client
    
    @transaction.atomic
    def rotate_credentials(self, rotation_reason: str = "Scheduled rotation") -> Dict[str, Any]:
        """
        Rotate client credentials with proper transition handling.
        
        Args:
            rotation_reason (str): Reason for credential rotation
            
        Returns:
            Dict containing new credentials and transition information
        """
        logger.info(f"Starting credential rotation for client {self.client.client_name}")
        
        # Store old credentials for transition period
        old_api_key_hash = self.client.api_key_hash
        old_signing_key = self.client.signing_key
        
        # Generate new credentials
        new_credentials = generate_client_credentials()
        
        # Update client with new credentials
        self.client.api_key_hash = new_credentials['api_key_hash']
        self.client.signing_key = new_credentials['signing_key']
        self.client.updated_at = timezone.now()
        self.client.save()
        
        # Create rotation record for audit trail
        rotation_record = self._create_rotation_record(
            old_api_key_hash, 
            old_signing_key, 
            rotation_reason
        )
        
        # Schedule old credential cleanup
        cleanup_time = timezone.now() + timedelta(hours=24)  # 24-hour transition period
        
        logger.info(f"Credential rotation completed for client {self.client.client_name}")
        
        return {
            'client_id': str(self.client.client_id),
            'new_credentials': {
                'api_key': new_credentials['api_key'],
                'signing_key': new_credentials['signing_key'],
                'public_key': new_credentials['public_key']
            },
            'transition_period': {
                'old_signing_key': old_signing_key,
                'old_public_key': ClientCredentialManager.get_public_key_from_private(old_signing_key),
                'cleanup_time': cleanup_time.isoformat()
            },
            'rotation_record': rotation_record
        }
    
    def _create_rotation_record(self, old_api_key_hash: str, old_signing_key: str, reason: str) -> Dict[str, Any]:
        """
        Create an audit record for credential rotation.
        """
        rotation_record = {
            'client_id': str(self.client.client_id),
            'client_name': self.client.client_name,
            'rotation_time': timezone.now().isoformat(),
            'reason': reason,
            'old_api_key_hash': old_api_key_hash[:16] + "...",  # Partial hash for audit
            'new_api_key_hash': self.client.api_key_hash[:16] + "...",
            'rotated_by': 'system'  # Could be enhanced to track user
        }
        
        # Log the rotation
        logger.info(f"Credential rotation record created: {rotation_record}")
        
        return rotation_record
    
    @transaction.atomic
    def emergency_rotation(self, reason: str = "Emergency rotation") -> Dict[str, Any]:
        """
        Perform emergency credential rotation with immediate token revocation.
        
        Args:
            reason (str): Reason for emergency rotation
            
        Returns:
            Dict containing new credentials and revocation information
        """
        logger.warning(f"Emergency credential rotation initiated for client {self.client.client_name}")
        
        # Revoke all existing refresh tokens immediately
        revoked_tokens = self._revoke_all_refresh_tokens(reason)
        
        # Perform credential rotation
        rotation_result = self.rotate_credentials(reason)
        
        # Add revocation information
        rotation_result['emergency_actions'] = {
            'revoked_tokens_count': revoked_tokens,
            'immediate_effect': True,
            'transition_period': None  # No transition period for emergency rotation
        }
        
        logger.warning(f"Emergency credential rotation completed for client {self.client.client_name}")
        
        return rotation_result
    
    def _revoke_all_refresh_tokens(self, reason: str) -> int:
        """
        Revoke all refresh tokens for the client.
        
        Returns:
            Number of tokens revoked
        """
        # Get all active refresh tokens for this client
        active_tokens = RefreshToken.objects.filter(
            client=self.client,
            is_revoked=False
        )
        
        revoked_count = 0
        
        for token in active_tokens:
            # Mark token as revoked
            token.is_revoked = True
            token.save()
            
            # Add to blacklist for additional security
            try:
                # Extract JWT ID from token if possible
                jwt_auth = JWTAuthentication()
                payload = jwt_auth.decode_token(token.token)
                jti = payload.get('jti')
                
                if jti:
                    BlacklistedToken.objects.create(
                        token_jti=jti,
                        user=token.user,
                        reason=f"Emergency rotation: {reason}",
                        expires_at=token.expires_at,
                        client=self.client,
                        client_type=self.client.client_type,
                        violation_reason="Credential rotation"
                    )
            except Exception as e:
                logger.error(f"Failed to blacklist token during rotation: {e}")
            
            revoked_count += 1
        
        logger.info(f"Revoked {revoked_count} refresh tokens for client {self.client.client_name}")
        return revoked_count
    
    def validate_transition_period(self, old_signing_key: str) -> bool:
        """
        Validate if we're still in the transition period for old credentials.
        
        Args:
            old_signing_key (str): The old signing key to validate
            
        Returns:
            bool: True if still in transition period
        """
        # In a real implementation, you'd store transition periods in the database
        # For now, we'll assume a 24-hour transition period from last update
        transition_cutoff = self.client.updated_at + timedelta(hours=24)
        return timezone.now() < transition_cutoff
    
    def cleanup_old_credentials(self) -> Dict[str, Any]:
        """
        Clean up old credentials after transition period.
        
        Returns:
            Dict with cleanup results
        """
        # This would typically be called by a scheduled task
        # to clean up old credentials after the transition period
        
        cleanup_time = timezone.now()
        
        # In a real implementation, you'd have a table to track old credentials
        # and clean them up here
        
        logger.info(f"Credential cleanup completed for client {self.client.client_name}")
        
        return {
            'client_id': str(self.client.client_id),
            'cleanup_time': cleanup_time.isoformat(),
            'status': 'completed'
        }


class RotationScheduler:
    """
    Handles scheduled credential rotation for clients.
    """
    
    @staticmethod
    def should_rotate_credentials(client: RegisteredClient, rotation_interval_days: int = 90) -> bool:
        """
        Check if client credentials should be rotated based on age.
        
        Args:
            client (RegisteredClient): The client to check
            rotation_interval_days (int): Rotation interval in days
            
        Returns:
            bool: True if credentials should be rotated
        """
        if not client.updated_at:
            return True  # No update time means very old credentials
        
        rotation_due = client.updated_at + timedelta(days=rotation_interval_days)
        return timezone.now() >= rotation_due
    
    @staticmethod
    def get_rotation_schedule(client: RegisteredClient) -> Dict[str, Any]:
        """
        Get rotation schedule information for a client.
        
        Args:
            client (RegisteredClient): The client to check
            
        Returns:
            Dict with schedule information
        """
        rotation_interval = timedelta(days=90)  # Default 90 days
        
        if client.updated_at:
            next_rotation = client.updated_at + rotation_interval
            days_until_rotation = (next_rotation - timezone.now()).days
        else:
            next_rotation = timezone.now()
            days_until_rotation = 0
        
        return {
            'client_id': str(client.client_id),
            'last_rotation': client.updated_at.isoformat() if client.updated_at else None,
            'next_rotation': next_rotation.isoformat(),
            'days_until_rotation': max(0, days_until_rotation),
            'rotation_overdue': days_until_rotation < 0
        }
    
    @staticmethod
    def rotate_all_due_clients() -> Dict[str, Any]:
        """
        Rotate credentials for all clients that are due for rotation.
        
        Returns:
            Dict with rotation results
        """
        due_clients = []
        rotation_results = []
        errors = []
        
        # Find all clients due for rotation
        for client in RegisteredClient.objects.filter(is_active=True):
            if RotationScheduler.should_rotate_credentials(client):
                due_clients.append(client)
        
        logger.info(f"Found {len(due_clients)} clients due for credential rotation")
        
        # Rotate credentials for each due client
        for client in due_clients:
            try:
                rotation_manager = CredentialRotationManager(client)
                result = rotation_manager.rotate_credentials("Scheduled rotation")
                rotation_results.append({
                    'client_id': str(client.client_id),
                    'client_name': client.client_name,
                    'status': 'success',
                    'rotation_time': result['rotation_record']['rotation_time']
                })
                logger.info(f"Successfully rotated credentials for {client.client_name}")
            except Exception as e:
                error_info = {
                    'client_id': str(client.client_id),
                    'client_name': client.client_name,
                    'error': str(e)
                }
                errors.append(error_info)
                logger.error(f"Failed to rotate credentials for {client.client_name}: {e}")
        
        return {
            'total_due': len(due_clients),
            'successful_rotations': len(rotation_results),
            'failed_rotations': len(errors),
            'results': rotation_results,
            'errors': errors,
            'execution_time': timezone.now().isoformat()
        }
