import json
import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import re

from .models import RegisteredClient, AuthenticationAttempt
from .client_utils import ClientCredentialManager
from .rate_limiting import RateLimitManager
from .domain_validation import DomainValidationManager
from .security_monitoring import SecurityMonitoringManager

logger = logging.getLogger(__name__)


class ClientAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware to authenticate and validate client applications.
    Enforces client-specific security policies and rate limiting.
    """
    
    def __init__(self, get_response=None):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """
        Process incoming requests to validate client authentication.
        """
        # Skip client authentication for certain paths
        if self._should_skip_client_auth(request):
            return None
        
        # Only process GraphQL requests that require client authentication
        if not self._requires_client_auth(request):
            return None
        
        # Extract client credentials from request
        client_id, api_key = self._extract_client_credentials(request)
        
        if not client_id or not api_key:
            return self._create_error_response(
                "Client credentials required",
                status=401
            )
        
        # Validate client credentials
        client = self._validate_client_credentials(client_id, api_key, request)
        
        if not client:
            return self._create_error_response(
                "Invalid client credentials",
                status=401
            )
        
        # Check if client is active
        if not client.is_active:
            return self._create_error_response(
                "Client is not active",
                status=403
            )
        
        # Validate domain if required
        if not self._validate_client_domain(client, request):
            return self._create_error_response(
                "Domain not allowed for this client",
                status=403
            )
        
        # Apply rate limiting
        if not self._check_rate_limit(client, request):
            return self._create_error_response(
                "Rate limit exceeded",
                status=429
            )
        
        # Store client information in request for later use
        request.client = client
        request.client_type = client.client_type
        
        # Log successful client authentication using security monitoring
        SecurityMonitoringManager.record_client_authentication(
            client=client,
            success=True,
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            additional_context={
                'path': request.path,
                'method': request.method,
                'timestamp': timezone.now().isoformat()
            }
        )
        
        return None

    def process_response(self, request, response):
        """
        Add rate limiting headers to the response.
        """
        if hasattr(request, '_rate_limit_headers'):
            for header, value in request._rate_limit_headers.items():
                response[header] = value

        return response

    def _should_skip_client_auth(self, request):
        """
        Determine if client authentication should be skipped for this request.
        """
        skip_paths = [
            '/admin/',
            '/accounts/',
            '/static/',
            '/media/',
            '/health/',
            '/favicon.ico'
        ]
        
        return any(request.path.startswith(path) for path in skip_paths)
    
    def _requires_client_auth(self, request):
        """
        Determine if the request requires client authentication.
        """
        # Only GraphQL requests require client authentication
        if 'graphql' not in request.path.lower():
            return False
        
        # Check if it's a mutation that requires client auth
        if request.method == 'POST':
            try:
                body = json.loads(request.body.decode('utf-8'))
                query = body.get('query', '')
                
                # List of mutations that require client authentication
                client_auth_mutations = [
                    'register',
                    'login',
                    'refreshToken',
                    'logout',
                    'verifyMfa',
                    'getScopedAccessToken',
                    'initiatePatientAuth',
                    'completePatientAuth',
                    'registerProvider',
                    'loginProvider',
                    'verifyProviderTotp'
                ]
                
                # Check if any of these mutations are in the query
                return any(mutation in query for mutation in client_auth_mutations)
            
            except (json.JSONDecodeError, UnicodeDecodeError):
                # If we can't parse the request, require client auth for safety
                return True
        
        return False
    
    def _extract_client_credentials(self, request):
        """
        Extract client credentials from request headers.
        """
        # Check for credentials in headers
        client_id = request.META.get('HTTP_X_CLIENT_ID')
        api_key = request.META.get('HTTP_X_API_KEY')
        
        # Also check in POST body for GraphQL requests
        if not client_id or not api_key:
            try:
                if request.method == 'POST' and request.body:
                    body = json.loads(request.body.decode('utf-8'))
                    variables = body.get('variables', {})
                    client_id = client_id or variables.get('clientId')
                    api_key = api_key or variables.get('clientApiKey')
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        
        return client_id, api_key
    
    def _validate_client_credentials(self, client_id, api_key, request):
        """
        Validate client credentials against the database.
        """
        try:
            # Get client from database
            client = RegisteredClient.objects.get(client_id=client_id)
            
            # Validate API key
            if ClientCredentialManager.validate_client_credentials(
                client_id, api_key, client.api_key_hash
            ):
                return client
            else:
                SecurityMonitoringManager.record_client_authentication(
                    client=client,
                    success=False,
                    ip_address=self._get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    failure_reason="Invalid API key",
                    additional_context={
                        'path': request.path,
                        'method': request.method,
                        'timestamp': timezone.now().isoformat()
                    }
                )
                return None
                
        except RegisteredClient.DoesNotExist:
            self._log_client_authentication(None, request, success=False,
                                          reason="Client not found", client_id=client_id)
            return None
    
    def _validate_client_domain(self, client, request):
        """
        Validate that the request comes from an allowed domain.
        """
        # Use the enhanced domain validation system
        headers = {
            'origin': request.META.get('HTTP_ORIGIN'),
            'referer': request.META.get('HTTP_REFERER')
        }

        validation_result = DomainValidationManager.validate_request_headers(client, headers)

        if not validation_result['overall_valid']:
            # Log detailed validation failure
            logger.warning(
                f"Domain validation failed for client {client.client_id}: "
                f"{validation_result['validations']}"
            )

        return validation_result['overall_valid']
    

    
    def _check_rate_limit(self, client, request):
        """
        Check if the client has exceeded its rate limit.
        """
        # Get client IP for more granular rate limiting
        client_ip = self._get_client_ip(request)
        identifier = f"ip:{client_ip}"

        # Use the advanced rate limiting system
        rate_limit_result = RateLimitManager.check_client_rate_limit(client, identifier)

        if not rate_limit_result['allowed']:
            logger.warning(
                f"Rate limit exceeded for client {client.client_id} from IP {client_ip}: "
                f"{rate_limit_result['current_count']}/{rate_limit_result['limit']}"
            )
            return False

        # Add rate limit headers to response (will be handled in process_response)
        if hasattr(request, '_rate_limit_headers'):
            request._rate_limit_headers = RateLimitManager.get_rate_limit_headers(rate_limit_result)

        return True
    
    def _log_client_authentication(self, client, request, success, reason=None, client_id=None):
        """
        Log client authentication attempts.
        """
        try:
            AuthenticationAttempt.objects.create(
                email=None,  # Client auth doesn't have email
                attempt_type='client_auth',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=success,
                failure_reason=reason,
                client=client,
                client_type=client.client_type if client else None,
                security_context={
                    'client_id': str(client.client_id) if client else client_id,
                    'path': request.path,
                    'method': request.method,
                    'timestamp': timezone.now().isoformat()
                }
            )
        except Exception as e:
            logger.error(f"Failed to log client authentication attempt: {e}")
    
    def _get_client_ip(self, request):
        """
        Get the client's IP address from the request.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _create_error_response(self, message, status=400):
        """
        Create a standardized error response.
        """
        return JsonResponse({
            'errors': [{
                'message': message,
                'code': 'CLIENT_AUTH_ERROR'
            }]
        }, status=status)


class ClientSecurityPolicyMiddleware(MiddlewareMixin):
    """
    Middleware to enforce client-specific security policies.
    """
    
    def process_request(self, request):
        """
        Enforce security policies based on client configuration.
        """
        # Skip if no client is set (client auth middleware should run first)
        if not hasattr(request, 'client'):
            return None
        
        client = request.client
        
        # Enforce HTTPS for production clients
        if not self._check_https_requirement(client, request):
            return JsonResponse({
                'errors': [{
                    'message': 'HTTPS required for this client',
                    'code': 'HTTPS_REQUIRED'
                }]
            }, status=403)
        
        # Check device fingerprint requirement
        if client.require_device_fingerprint:
            if not self._validate_device_fingerprint(request):
                return JsonResponse({
                    'errors': [{
                        'message': 'Device fingerprint required',
                        'code': 'DEVICE_FINGERPRINT_REQUIRED'
                    }]
                }, status=403)
        
        return None
    
    def _check_https_requirement(self, client, request):
        """
        Check if HTTPS is required and enforced.
        """
        # Skip HTTPS check in development
        if settings.DEBUG:
            return True
        
        # For production, require HTTPS for sensitive client types
        sensitive_types = ['PROVIDER_WEB', 'PROVIDER_MOBILE', 'ADMIN_WEB']
        
        if client.client_type in sensitive_types:
            return request.is_secure()
        
        return True
    
    def _validate_device_fingerprint(self, request):
        """
        Validate device fingerprint if required.
        """
        fingerprint = request.META.get('HTTP_X_DEVICE_FINGERPRINT')
        
        # For now, just check if fingerprint is present
        # In a real implementation, you'd validate the fingerprint format
        return bool(fingerprint)
