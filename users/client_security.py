import logging
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from typing import Dict, Any, Optional

from .models import RegisteredClient, User

logger = logging.getLogger(__name__)


class ClientSecurityPolicy:
    """
    Handles client-specific security policy enforcement.
    """
    
    # Default security policies for each client type
    DEFAULT_POLICIES = {
        'PATIENT_WEB': {
            'max_requests_per_minute': 60,
            'token_lifetime_access': 60,  # minutes
            'token_lifetime_refresh': 43200,  # 30 days in minutes
            'require_device_fingerprint': True,
            'allow_social_login': False,
            'require_totp': False,
            'enhanced_monitoring': False,
            'allowed_auth_methods': ['passwordless'],
            'session_timeout': 3600,  # 1 hour in seconds
            'max_failed_attempts': 5,
            'lockout_duration': 900,  # 15 minutes in seconds
            'require_https': False,
            'allowed_origins': [],
        },
        'PATIENT_MOBILE': {
            'max_requests_per_minute': 100,
            'token_lifetime_access': 60,
            'token_lifetime_refresh': 43200,  # 30 days
            'require_device_fingerprint': True,
            'allow_social_login': False,
            'require_totp': False,
            'enhanced_monitoring': False,
            'allowed_auth_methods': ['passwordless'],
            'session_timeout': 3600,
            'max_failed_attempts': 5,
            'lockout_duration': 900,
            'require_https': False,
            'allowed_origins': [],
        },
        'PROVIDER_WEB': {
            'max_requests_per_minute': 120,
            'token_lifetime_access': 15,
            'token_lifetime_refresh': 10080,  # 7 days
            'require_device_fingerprint': False,
            'allow_social_login': True,
            'require_totp': True,
            'enhanced_monitoring': True,
            'allowed_auth_methods': ['email_password', 'social'],
            'session_timeout': 900,  # 15 minutes
            'max_failed_attempts': 3,
            'lockout_duration': 1800,  # 30 minutes
            'require_https': True,
            'allowed_origins': [],
        },
        'PROVIDER_MOBILE': {
            'max_requests_per_minute': 150,
            'token_lifetime_access': 15,
            'token_lifetime_refresh': 10080,  # 7 days
            'require_device_fingerprint': False,
            'allow_social_login': True,
            'require_totp': True,
            'enhanced_monitoring': True,
            'allowed_auth_methods': ['email_password', 'social'],
            'session_timeout': 900,
            'max_failed_attempts': 3,
            'lockout_duration': 1800,
            'require_https': True,
            'allowed_origins': [],
        },
        'ADMIN_WEB': {
            'max_requests_per_minute': 200,
            'token_lifetime_access': 15,
            'token_lifetime_refresh': 1440,  # 1 day
            'require_device_fingerprint': True,
            'allow_social_login': False,
            'require_totp': True,
            'enhanced_monitoring': True,
            'allowed_auth_methods': ['email_password'],
            'session_timeout': 900,
            'max_failed_attempts': 3,
            'lockout_duration': 3600,  # 1 hour
            'require_https': True,
            'allowed_origins': [],
        }
    }
    
    def __init__(self, client: RegisteredClient):
        self.client = client
        self.policy = self._build_policy()
    
    def _build_policy(self) -> Dict[str, Any]:
        """
        Build the complete security policy for the client.
        """
        # Start with default policy for client type
        default_policy = self.DEFAULT_POLICIES.get(
            self.client.client_type, 
            self.DEFAULT_POLICIES['PATIENT_WEB']
        ).copy()
        
        # Override with client-specific settings
        client_overrides = {
            'max_requests_per_minute': self.client.max_requests_per_minute,
            'token_lifetime_access': self.client.token_lifetime_access,
            'token_lifetime_refresh': self.client.token_lifetime_refresh,
            'require_device_fingerprint': self.client.require_device_fingerprint,
            'allow_social_login': self.client.allow_social_login,
            'require_totp': self.client.require_totp,
            'enhanced_monitoring': self.client.enhanced_monitoring,
        }
        
        # Merge policies
        default_policy.update(client_overrides)
        
        return default_policy
    
    def get_policy(self, key: str = None) -> Any:
        """
        Get a specific policy value or the entire policy.
        """
        if key:
            return self.policy.get(key)
        return self.policy
    
    def is_auth_method_allowed(self, auth_method: str) -> bool:
        """
        Check if an authentication method is allowed for this client.
        """
        allowed_methods = self.policy.get('allowed_auth_methods', [])
        return auth_method in allowed_methods
    
    def get_token_lifetime(self, token_type: str = 'access') -> int:
        """
        Get the token lifetime for the specified token type.
        """
        if token_type == 'refresh':
            return self.policy.get('token_lifetime_refresh', 10080)
        return self.policy.get('token_lifetime_access', 60)
    
    def requires_totp(self, user: Optional[User] = None) -> bool:
        """
        Check if TOTP is required for this client and user combination.
        """
        # Check client policy
        if self.policy.get('require_totp', False):
            return True
        
        # Check user role requirements
        if user:
            return user.requires_totp_for_client(self.client.client_type)
        
        return False
    
    def requires_device_fingerprint(self) -> bool:
        """
        Check if device fingerprinting is required.
        """
        return self.policy.get('require_device_fingerprint', False)
    
    def get_session_timeout(self) -> int:
        """
        Get the session timeout in seconds.
        """
        return self.policy.get('session_timeout', 3600)
    
    def get_max_failed_attempts(self) -> int:
        """
        Get the maximum number of failed authentication attempts.
        """
        return self.policy.get('max_failed_attempts', 5)
    
    def get_lockout_duration(self) -> int:
        """
        Get the lockout duration in seconds after max failed attempts.
        """
        return self.policy.get('lockout_duration', 900)
    
    def requires_https(self) -> bool:
        """
        Check if HTTPS is required for this client.
        """
        # Skip in development
        if settings.DEBUG:
            return False
        
        return self.policy.get('require_https', False)
    
    def is_enhanced_monitoring_enabled(self) -> bool:
        """
        Check if enhanced monitoring is enabled for this client.
        """
        return self.policy.get('enhanced_monitoring', False)
    
    def validate_request_context(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate request context against security policies.
        
        Returns:
            Dict with validation results and any violations
        """
        violations = []
        
        # Check HTTPS requirement
        if self.requires_https() and not request_data.get('is_secure', False):
            violations.append('HTTPS required for this client type')
        
        # Check device fingerprint requirement
        if (self.requires_device_fingerprint() and 
            not request_data.get('device_fingerprint')):
            violations.append('Device fingerprint required')
        
        # Check origin if specified
        allowed_origins = self.policy.get('allowed_origins', [])
        if allowed_origins:
            origin = request_data.get('origin')
            if origin and origin not in allowed_origins:
                violations.append(f'Origin {origin} not allowed')
        
        return {
            'valid': len(violations) == 0,
            'violations': violations
        }
    
    def get_rate_limit_key(self, identifier: str) -> str:
        """
        Generate a rate limit cache key for the client and identifier.
        """
        return f"rate_limit:{self.client.client_id}:{identifier}"
    
    def should_log_request(self, request_type: str) -> bool:
        """
        Determine if a request should be logged based on monitoring policy.
        """
        if self.is_enhanced_monitoring_enabled():
            return True
        
        # Always log authentication attempts and failures
        sensitive_requests = ['auth', 'login', 'register', 'password_reset']
        return request_type in sensitive_requests


class ClientSecurityManager:
    """
    Manager class for handling client security operations.
    """
    
    @staticmethod
    def get_policy_for_client(client_id: str) -> Optional[ClientSecurityPolicy]:
        """
        Get security policy for a client by ID.
        """
        try:
            client = RegisteredClient.objects.get(client_id=client_id, is_active=True)
            return ClientSecurityPolicy(client)
        except RegisteredClient.DoesNotExist:
            logger.warning(f"Client not found: {client_id}")
            return None
    
    @staticmethod
    def validate_client_request(client: RegisteredClient, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a client request against security policies.
        """
        policy = ClientSecurityPolicy(client)
        return policy.validate_request_context(request_data)
    
    @staticmethod
    def get_token_config_for_client(client: RegisteredClient, user: Optional[User] = None) -> Dict[str, Any]:
        """
        Get token configuration for a client and user combination.
        """
        policy = ClientSecurityPolicy(client)
        
        return {
            'access_token_lifetime': policy.get_token_lifetime('access'),
            'refresh_token_lifetime': policy.get_token_lifetime('refresh'),
            'requires_totp': policy.requires_totp(user),
            'requires_device_fingerprint': policy.requires_device_fingerprint(),
            'signing_key': client.signing_key,
            'client_id': str(client.client_id),
            'client_type': client.client_type
        }
    
    @staticmethod
    def check_authentication_method(client: RegisteredClient, auth_method: str) -> bool:
        """
        Check if an authentication method is allowed for a client.
        """
        policy = ClientSecurityPolicy(client)
        return policy.is_auth_method_allowed(auth_method)
    
    @staticmethod
    def get_security_context(client: RegisteredClient, user: Optional[User] = None) -> Dict[str, Any]:
        """
        Get complete security context for a client and user.
        """
        policy = ClientSecurityPolicy(client)
        
        return {
            'client_id': str(client.client_id),
            'client_type': client.client_type,
            'client_name': client.client_name,
            'requires_totp': policy.requires_totp(user),
            'requires_device_fingerprint': policy.requires_device_fingerprint(),
            'enhanced_monitoring': policy.is_enhanced_monitoring_enabled(),
            'session_timeout': policy.get_session_timeout(),
            'max_failed_attempts': policy.get_max_failed_attempts(),
            'lockout_duration': policy.get_lockout_duration(),
            'allowed_auth_methods': policy.get_policy('allowed_auth_methods'),
            'token_lifetimes': {
                'access': policy.get_token_lifetime('access'),
                'refresh': policy.get_token_lifetime('refresh')
            }
        }
