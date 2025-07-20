"""
Service authentication middleware and decorators.
Provides authentication and authorization for service-to-service communication.
"""

import logging
from functools import wraps
from typing import List, Optional, Callable, Any
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from graphql import GraphQLError

from .service_jwt import ServiceJWTManager
from .models import ServiceAccount

logger = logging.getLogger(__name__)


class ServiceAuthenticationMiddleware:
    """
    Middleware for authenticating service requests.
    Handles both HTTP and GraphQL service authentication.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Process service authentication for API requests
        if self._is_service_api_request(request):
            auth_result = self._authenticate_service_request(request)
            if not auth_result['success']:
                return JsonResponse({
                    'error': 'Service authentication failed',
                    'message': auth_result['error']
                }, status=401)
            
            # Add service info to request
            request.service_account = auth_result['service_account']
            request.service_token_payload = auth_result['payload']
        
        response = self.get_response(request)
        return response
    
    def _is_service_api_request(self, request) -> bool:
        """Check if this is a service API request."""
        # Check for service authentication header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Service '):
            return True
        
        # Check for service-specific endpoints
        service_endpoints = ['/api/service/', '/graphql/service/']
        return any(request.path.startswith(endpoint) for endpoint in service_endpoints)
    
    def _authenticate_service_request(self, request) -> dict:
        """Authenticate a service request."""
        try:
            # Extract token from Authorization header
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if not auth_header.startswith('Service '):
                return {
                    'success': False,
                    'error': 'Missing or invalid Authorization header'
                }
            
            token = auth_header[8:]  # Remove 'Service ' prefix
            
            # Validate service token
            payload = ServiceJWTManager.validate_service_token(token)
            
            return {
                'success': True,
                'service_account': payload['service_account'],
                'payload': payload
            }
            
        except Exception as e:
            logger.warning(f"Service authentication failed: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }


def require_service_auth(required_service_type: str = None, 
                        required_permissions: List[str] = None):
    """
    Decorator for requiring service authentication on views.
    
    Args:
        required_service_type (str, optional): Required service type
        required_permissions (list, optional): Required permissions
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Check if service is authenticated
            if not hasattr(request, 'service_account'):
                return JsonResponse({
                    'error': 'Service authentication required'
                }, status=401)
            
            # Validate service type if required
            if required_service_type:
                service_type = request.service_account['service_type']
                if service_type != required_service_type:
                    return JsonResponse({
                        'error': f'Service type {required_service_type} required'
                    }, status=403)
            
            # Validate permissions if required
            if required_permissions:
                available_permissions = request.service_token_payload.get('permissions', [])
                missing_permissions = []
                
                for perm in required_permissions:
                    if not ServiceJWTManager._has_permission(available_permissions, perm):
                        missing_permissions.append(perm)
                
                if missing_permissions:
                    return JsonResponse({
                        'error': f'Missing required permissions: {missing_permissions}'
                    }, status=403)
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def graphql_require_service_auth(required_service_type: str = None,
                                required_permissions: List[str] = None):
    """
    Decorator for requiring service authentication on GraphQL resolvers.
    
    Args:
        required_service_type (str, optional): Required service type
        required_permissions (list, optional): Required permissions
    """
    def decorator(resolver_func):
        @wraps(resolver_func)
        def wrapper(root, info, *args, **kwargs):
            request = info.context
            
            # Check for service authentication
            service_token = None
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            
            if auth_header.startswith('Service '):
                service_token = auth_header[8:]
            elif auth_header.startswith('Bearer '):
                # Check if it's a service token
                token = auth_header[7:]
                if ServiceJWTManager.is_service_token(token):
                    service_token = token
            
            if not service_token:
                raise GraphQLError("Service authentication required")
            
            try:
                # Validate service token
                payload = ServiceJWTManager.validate_service_token(
                    service_token,
                    required_service_type=required_service_type,
                    required_permissions=required_permissions
                )
                
                # Add service info to context
                request.service_account = payload['service_account']
                request.service_token_payload = payload
                
                return resolver_func(root, info, *args, **kwargs)
                
            except Exception as e:
                raise GraphQLError(f"Service authentication failed: {str(e)}")
        
        return wrapper
    return decorator


class ServiceAccountContext:
    """
    Context manager for service account operations.
    Provides easy access to service account information in resolvers.
    """
    
    def __init__(self, request):
        self.request = request
        self._service_account = None
        self._payload = None
    
    @property
    def is_service_authenticated(self) -> bool:
        """Check if request is authenticated as a service."""
        return hasattr(self.request, 'service_account')
    
    @property
    def service_account(self) -> Optional[dict]:
        """Get service account information."""
        return getattr(self.request, 'service_account', None)
    
    @property
    def service_id(self) -> Optional[str]:
        """Get service ID."""
        if self.service_account:
            return self.service_account.get('service_id')
        return None
    
    @property
    def service_type(self) -> Optional[str]:
        """Get service type."""
        if self.service_account:
            return self.service_account.get('service_type')
        return None
    
    @property
    def permissions(self) -> List[str]:
        """Get service permissions."""
        payload = getattr(self.request, 'service_token_payload', {})
        return payload.get('permissions', [])
    
    @property
    def scoped_permissions(self) -> List[str]:
        """Get scoped permissions for target service."""
        payload = getattr(self.request, 'service_token_payload', {})
        return payload.get('scoped_permissions', self.permissions)
    
    @property
    def target_service(self) -> Optional[str]:
        """Get target service if token is scoped."""
        payload = getattr(self.request, 'service_token_payload', {})
        return payload.get('target_service')
    
    def has_permission(self, permission: str) -> bool:
        """Check if service has a specific permission."""
        return ServiceJWTManager._has_permission(self.scoped_permissions, permission)
    
    def require_permission(self, permission: str):
        """Require a specific permission, raise error if not available."""
        if not self.has_permission(permission):
            raise GraphQLError(f"Service permission required: {permission}")
    
    def require_service_type(self, service_type: str):
        """Require a specific service type, raise error if not match."""
        if self.service_type != service_type:
            raise GraphQLError(f"Service type {service_type} required")


def get_service_context(info) -> ServiceAccountContext:
    """
    Get service account context from GraphQL info.
    
    Args:
        info: GraphQL resolve info
        
    Returns:
        ServiceAccountContext: Service context manager
    """
    return ServiceAccountContext(info.context)


# Service authentication utilities
class ServiceAuthUtils:
    """Utility functions for service authentication."""
    
    @staticmethod
    def create_service_auth_header(token: str) -> dict:
        """Create authorization header for service requests."""
        return {'Authorization': f'Service {token}'}
    
    @staticmethod
    def extract_service_token(request) -> Optional[str]:
        """Extract service token from request."""
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if auth_header.startswith('Service '):
            return auth_header[8:]
        elif auth_header.startswith('Bearer '):
            token = auth_header[7:]
            if ServiceJWTManager.is_service_token(token):
                return token
        
        return None
    
    @staticmethod
    def validate_service_request(request, required_service_type: str = None,
                                required_permissions: List[str] = None) -> dict:
        """
        Validate a service request and return validation result.
        
        Returns:
            dict: Validation result with success, service_account, and error info
        """
        try:
            token = ServiceAuthUtils.extract_service_token(request)
            if not token:
                return {
                    'success': False,
                    'error': 'No service token found'
                }
            
            payload = ServiceJWTManager.validate_service_token(
                token,
                required_service_type=required_service_type,
                required_permissions=required_permissions
            )
            
            return {
                'success': True,
                'service_account': payload['service_account'],
                'payload': payload
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
