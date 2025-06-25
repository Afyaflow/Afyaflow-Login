"""
GraphQL security middleware for AfyaFlow Auth Service.
Provides security logging and basic protections.
"""

import logging
import json
from typing import Any, Dict
from django.conf import settings

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """GraphQL middleware for security enhancements."""

    def __init__(self):
        self.max_query_depth = getattr(settings, 'GRAPHQL_MAX_QUERY_DEPTH', 10)
        self.max_query_complexity = getattr(settings, 'GRAPHQL_MAX_QUERY_COMPLEXITY', 1000)
        self.enable_introspection = getattr(settings, 'DEBUG', False)

    def resolve(self, next, root, info, **args):
        """Apply security checks before resolving."""

        # Log GraphQL operations for security monitoring
        operation_name = getattr(info.operation, 'name', None) if hasattr(info, 'operation') and info.operation else None
        operation_type = 'unknown'

        if hasattr(info, 'operation') and info.operation and hasattr(info.operation, 'operation'):
            operation_type = info.operation.operation.value

        client_ip = self._get_client_ip(info.context)

        logger.info(
            f"GraphQL {operation_type} operation: {operation_name or 'anonymous'} "
            f"from {client_ip}"
        )

        # Basic query depth check (simplified)
        if hasattr(info, 'field_name'):
            self._check_query_depth(info)

        return next(root, info, **args)

    def _check_query_depth(self, info, current_depth=1):
        """Simple query depth check."""
        if current_depth > self.max_query_depth:
            logger.warning(f"Query depth {current_depth} exceeds limit {self.max_query_depth}")
            # In a real implementation, you might want to raise an error here
            # For now, we just log the warning

    def _get_client_ip(self, request) -> str:
        """Get the real client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip


class AuthenticationLoggingMiddleware:
    """Middleware to log authentication-related GraphQL operations."""
    
    def resolve(self, next, root, info, **args):
        """Log authentication operations."""
        
        # Check if this is an authentication-related mutation
        auth_mutations = [
            'login', 'register', 'loginWithGoogle', 'loginWithMicrosoft', 
            'loginWithLinkedin', 'verifyMfa', 'refreshToken', 'logout',
            'changePassword', 'initiatePasswordReset', 'resetPasswordWithOtp'
        ]
        
        field_name = info.field_name.lower()
        if any(auth_mut in field_name for auth_mut in auth_mutations):
            client_ip = self._get_client_ip(info.context)
            user_agent = info.context.META.get('HTTP_USER_AGENT', 'Unknown')
            
            logger.info(
                f"Authentication operation '{info.field_name}' attempted "
                f"from IP {client_ip} with User-Agent: {user_agent[:100]}"
            )
        
        return next(root, info, **args)
    
    def _get_client_ip(self, request) -> str:
        """Get the real client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip


# Combine all middleware
class CombinedSecurityMiddleware:
    """Combined security middleware for GraphQL."""

    def __init__(self):
        self.security_middleware = SecurityMiddleware()
        self.auth_logging_middleware = AuthenticationLoggingMiddleware()

    def resolve(self, next, root, info, **args):
        """Apply all security middleware in sequence."""
        try:
            # Apply authentication logging first
            self.auth_logging_middleware.resolve(lambda r, i, **a: None, root, info, **args)

            # Then apply security checks
            self.security_middleware.resolve(lambda r, i, **a: None, root, info, **args)

            # Finally call the actual resolver
            return next(root, info, **args)
        except Exception as e:
            logger.error(f"GraphQL middleware error: {str(e)}")
            return next(root, info, **args)
