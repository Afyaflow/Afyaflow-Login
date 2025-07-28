"""
Service-to-Service Authentication for AfyaFlow Auth Service.
Implements X-Service-Auth-ID header validation and service account management.
"""

import logging
import os
from typing import Dict, Optional, Tuple
from django.conf import settings
from django.contrib.auth.models import AnonymousUser

logger = logging.getLogger(__name__)


class ServiceAccount:
    """Represents a service account with its configuration."""
    
    def __init__(self, service_id: str, service_type: str, permissions: list):
        self.service_id = service_id
        self.service_type = service_type
        self.permissions = permissions
    
    def __str__(self):
        return f"ServiceAccount({self.service_id}, {self.service_type})"


class ServiceAuthenticationError(Exception):
    """Raised when service authentication fails."""
    pass


def get_service_account_config() -> Dict[str, ServiceAccount]:
    """
    Load service account configuration from environment variables.
    
    Environment variables pattern:
    SERVICE_ACCOUNT_IDS="service1,service2,service3"
    SERVICE_ACCOUNT_SERVICE1_TYPE="document-management"
    SERVICE_ACCOUNT_SERVICE1_PERMISSIONS="read:documents,write:documents"
    
    Returns:
        Dict mapping service IDs to ServiceAccount objects
    """
    service_accounts = {}
    
    # Get list of service account IDs
    service_ids_str = os.getenv('SERVICE_ACCOUNT_IDS', '')
    if not service_ids_str:
        logger.warning("No SERVICE_ACCOUNT_IDS configured")
        return service_accounts
    
    service_ids = [sid.strip() for sid in service_ids_str.split(',') if sid.strip()]
    
    for service_id in service_ids:
        # Normalize service ID for environment variable names
        normalized_id = service_id.replace('-', '_').replace('.', '_').upper()
        
        # Get service type
        type_key = f'SERVICE_ACCOUNT_{normalized_id}_TYPE'
        service_type = os.getenv(type_key)
        
        # Get permissions
        perms_key = f'SERVICE_ACCOUNT_{normalized_id}_PERMISSIONS'
        permissions_str = os.getenv(perms_key, '')
        permissions = [p.strip() for p in permissions_str.split(',') if p.strip()]
        
        if service_type:
            service_accounts[service_id] = ServiceAccount(
                service_id=service_id,
                service_type=service_type,
                permissions=permissions
            )
            logger.info(f"Loaded service account: {service_id} ({service_type})")
        else:
            logger.warning(f"Service account {service_id} missing type configuration ({type_key})")
    
    return service_accounts


def validate_service_account(service_id: str) -> Optional[ServiceAccount]:
    """
    Validate a service account ID and return the service account if valid.
    
    Args:
        service_id: The service account ID from X-Service-Auth-ID header
        
    Returns:
        ServiceAccount object if valid, None otherwise
    """
    if not service_id:
        return None
    
    service_accounts = get_service_account_config()
    return service_accounts.get(service_id)


def get_auth_service_id() -> str:
    """
    Get the service ID for this auth service when making outgoing requests.
    
    Returns:
        The service ID for this auth service
    """
    return os.getenv('AUTH_SERVICE_ID', 'auth-service')


class ServiceUser:
    """
    Represents a service account as a user-like object for authentication context.
    This allows service accounts to be treated like users in GraphQL resolvers.
    """
    
    def __init__(self, service_account: ServiceAccount):
        self.service_account = service_account
        self.id = f"service:{service_account.service_id}"
        self.email = f"{service_account.service_id}@service.local"
        self.first_name = service_account.service_type.title()
        self.last_name = "Service"
        self.is_authenticated = True
        self.is_service = True
        self.is_active = True
        self.is_staff = False
        self.is_superuser = False
        self.user_type = 'service'
    
    def __str__(self):
        return f"ServiceUser({self.service_account.service_id})"
    
    def has_permission(self, permission: str) -> bool:
        """Check if the service has a specific permission."""
        return permission in self.service_account.permissions
    
    def get_permissions(self) -> list:
        """Get all permissions for this service."""
        return self.service_account.permissions.copy()


class ServiceAuthMiddleware:
    """
    Django middleware to handle X-Service-Auth-ID header authentication.
    This middleware runs before JWT authentication and takes precedence.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.service_accounts = get_service_account_config()
        logger.info(f"ServiceAuthMiddleware initialized with {len(self.service_accounts)} service accounts")
    
    def __call__(self, request):
        # Check for X-Service-Auth-ID header
        service_id = request.META.get('HTTP_X_SERVICE_AUTH_ID')
        
        if service_id:
            # Validate service account
            service_account = validate_service_account(service_id)
            
            if service_account:
                # Set service user in request
                request.user = ServiceUser(service_account)
                request.service_authenticated = True
                request.service_account = service_account
                
                logger.info(f"Service authenticated: {service_id} ({service_account.service_type})")
            else:
                logger.warning(f"Invalid service account ID: {service_id}")
                # Don't set user, let normal authentication handle it
                request.service_authenticated = False
        else:
            request.service_authenticated = False
        
        return self.get_response(request)


def create_service_auth_headers(target_service: Optional[str] = None) -> Dict[str, str]:
    """
    Create headers for outgoing service-to-service requests.
    
    Args:
        target_service: Optional target service identifier for logging
        
    Returns:
        Dictionary of headers including X-Service-Auth-ID
    """
    auth_service_id = get_auth_service_id()
    
    headers = {
        'X-Service-Auth-ID': auth_service_id,
        'Content-Type': 'application/json',
    }
    
    if target_service:
        logger.debug(f"Creating service auth headers for {auth_service_id} -> {target_service}")
    
    return headers


def is_service_request(request) -> bool:
    """
    Check if the current request is from a service account.
    
    Args:
        request: Django request object
        
    Returns:
        True if request is service-authenticated
    """
    return getattr(request, 'service_authenticated', False)


def get_service_context(request) -> Optional[ServiceAccount]:
    """
    Get the service account context from the request.

    Args:
        request: Django request object

    Returns:
        ServiceAccount if service-authenticated, None otherwise
    """
    if is_service_request(request):
        return getattr(request, 'service_account', None)
    return None


def require_service_permission(permission: str):
    """
    Decorator to require a specific service permission for GraphQL resolvers.

    Args:
        permission: The required permission string

    Returns:
        Decorator function
    """
    def decorator(resolver_func):
        def wrapper(root, info, *args, **kwargs):
            request = info.context

            if not is_service_request(request):
                from graphql import GraphQLError
                raise GraphQLError("This operation requires service authentication.")

            service_account = get_service_context(request)
            if not service_account or permission not in service_account.permissions:
                from graphql import GraphQLError
                raise GraphQLError(f"Service does not have required permission: {permission}")

            return resolver_func(root, info, *args, **kwargs)
        return wrapper
    return decorator


def get_auth_context(info):
    """
    Get authentication context from GraphQL info object.

    Args:
        info: GraphQL info object

    Returns:
        Dict with authentication context information
    """
    request = info.context

    context = {
        'is_authenticated': False,
        'is_service': False,
        'user': None,
        'service_account': None,
        'permissions': []
    }

    if is_service_request(request):
        service_account = get_service_context(request)
        context.update({
            'is_authenticated': True,
            'is_service': True,
            'service_account': service_account,
            'permissions': service_account.permissions if service_account else []
        })
    elif hasattr(request, 'user') and request.user.is_authenticated:
        context.update({
            'is_authenticated': True,
            'is_service': False,
            'user': request.user,
            'permissions': []  # User permissions would be handled differently
        })

    return context
