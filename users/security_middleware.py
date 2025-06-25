"""
Security middleware for AfyaFlow Auth Service.
Provides rate limiting, authentication attempt tracking, and security headers.
"""

import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional
from django.core.cache import cache
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import AnonymousUser
from django.db import transaction
from .models import User

logger = logging.getLogger(__name__)


class AuthenticationAttemptTracker:
    """Track and manage authentication attempts for security monitoring."""
    
    def __init__(self):
        self.cache_timeout = 900  # 15 minutes
        self.max_attempts = getattr(settings, 'MAX_AUTH_ATTEMPTS_PER_IP', 10)
        self.lockout_duration = getattr(settings, 'AUTH_LOCKOUT_DURATION_MINUTES', 15)
    
    def get_cache_key(self, identifier: str, attempt_type: str = 'login') -> str:
        """Generate cache key for tracking attempts."""
        return f"auth_attempts:{attempt_type}:{identifier}"
    
    def get_lockout_key(self, identifier: str, attempt_type: str = 'login') -> str:
        """Generate cache key for lockout status."""
        return f"auth_lockout:{attempt_type}:{identifier}"
    
    def is_locked_out(self, identifier: str, attempt_type: str = 'login') -> bool:
        """Check if identifier is currently locked out."""
        lockout_key = self.get_lockout_key(identifier, attempt_type)
        return cache.get(lockout_key, False)
    
    def record_attempt(self, identifier: str, success: bool, attempt_type: str = 'login', 
                      user_email: str = None, failure_reason: str = None) -> Dict:
        """Record an authentication attempt and return current status."""
        cache_key = self.get_cache_key(identifier, attempt_type)
        lockout_key = self.get_lockout_key(identifier, attempt_type)
        
        # Get current attempts
        attempts_data = cache.get(cache_key, {'count': 0, 'first_attempt': time.time()})
        
        if success:
            # Clear attempts on successful authentication
            cache.delete(cache_key)
            cache.delete(lockout_key)
            logger.info(f"Successful {attempt_type} for {user_email or identifier}")
            return {'locked_out': False, 'attempts_remaining': self.max_attempts}
        
        # Increment failed attempts
        attempts_data['count'] += 1
        attempts_data['last_attempt'] = time.time()
        
        # Log the failed attempt
        logger.warning(
            f"Failed {attempt_type} attempt for {user_email or identifier}. "
            f"Attempt {attempts_data['count']}/{self.max_attempts}. "
            f"Reason: {failure_reason or 'Unknown'}"
        )
        
        # Check if we should lock out
        if attempts_data['count'] >= self.max_attempts:
            cache.set(lockout_key, True, self.lockout_duration * 60)
            cache.delete(cache_key)  # Clear attempts counter
            logger.error(
                f"Account locked out for {user_email or identifier} after "
                f"{attempts_data['count']} failed {attempt_type} attempts"
            )
            return {'locked_out': True, 'attempts_remaining': 0}
        
        # Update attempts cache
        cache.set(cache_key, attempts_data, self.cache_timeout)
        
        attempts_remaining = self.max_attempts - attempts_data['count']
        return {'locked_out': False, 'attempts_remaining': attempts_remaining}


class RateLimitMiddleware:
    """Rate limiting middleware for GraphQL and API endpoints."""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.rate_limits = {
            'graphql': {'requests': 60, 'window': 60},  # 60 requests per minute
            'auth': {'requests': 10, 'window': 60},     # 10 auth requests per minute
            'default': {'requests': 100, 'window': 60}  # 100 requests per minute
        }
    
    def __call__(self, request):
        # Skip rate limiting for admin and health check
        if request.path.startswith('/admin/') or request.path == '/health/':
            return self.get_response(request)
        
        # Determine rate limit type
        if 'graphql' in request.path:
            limit_type = 'graphql'
        elif any(auth_path in request.path for auth_path in ['/api/auth/', '/accounts/']):
            limit_type = 'auth'
        else:
            limit_type = 'default'
        
        # Check rate limit
        client_ip = self.get_client_ip(request)
        if self.is_rate_limited(client_ip, limit_type):
            logger.warning(f"Rate limit exceeded for IP {client_ip} on {request.path}")
            return JsonResponse(
                {'error': 'Rate limit exceeded. Please try again later.'},
                status=429
            )
        
        return self.get_response(request)
    
    def get_client_ip(self, request) -> str:
        """Get the real client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip
    
    def is_rate_limited(self, identifier: str, limit_type: str) -> bool:
        """Check if the identifier has exceeded the rate limit."""
        config = self.rate_limits.get(limit_type, self.rate_limits['default'])
        cache_key = f"rate_limit:{limit_type}:{identifier}"
        
        current_time = int(time.time())
        window_start = current_time - config['window']
        
        # Get current requests in the window
        requests = cache.get(cache_key, [])
        
        # Filter requests within the current window
        requests = [req_time for req_time in requests if req_time > window_start]
        
        # Check if limit exceeded
        if len(requests) >= config['requests']:
            return True
        
        # Add current request
        requests.append(current_time)
        cache.set(cache_key, requests, config['window'])
        
        return False


class SecurityHeadersMiddleware:
    """Add security headers to all responses."""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Add CSP for GraphQL endpoint
        if 'graphql' in request.path:
            if getattr(settings, 'DEBUG', False):
                # Skip CSP in development to allow GraphiQL to work properly
                # GraphiQL needs to load external resources from CDN
                pass  # No CSP header in development
            else:
                # Strict CSP for production
                response['Content-Security-Policy'] = (
                    "default-src 'self'; "
                    "script-src 'self'; "
                    "style-src 'self'; "
                    "img-src 'self' data:; "
                    "connect-src 'self'"
                )
        
        return response


# Global instance for use in GraphQL mutations
auth_attempt_tracker = AuthenticationAttemptTracker()
