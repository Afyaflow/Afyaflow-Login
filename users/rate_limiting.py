import time
import logging
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from typing import Optional, Dict, Any

from .models import RegisteredClient

logger = logging.getLogger(__name__)


class ClientRateLimiter:
    """
    Rate limiter for client applications with configurable limits and windows.
    """
    
    def __init__(self, client: RegisteredClient):
        self.client = client
        self.cache_prefix = f"rate_limit:{client.client_id}"
        
    def is_allowed(self, identifier: str = None, window_seconds: int = 60) -> Dict[str, Any]:
        """
        Check if a request is allowed based on rate limiting rules.
        
        Args:
            identifier (str, optional): Additional identifier (e.g., user_id, ip_address)
            window_seconds (int): Time window in seconds (default: 60)
            
        Returns:
            Dict containing allowed status, current count, limit, and reset time
        """
        # Create cache key
        cache_key = self._get_cache_key(identifier)
        
        # Get current count and timestamp
        current_data = cache.get(cache_key, {'count': 0, 'window_start': time.time()})
        current_time = time.time()
        
        # Check if we need to reset the window
        if current_time - current_data['window_start'] >= window_seconds:
            # Reset the window
            current_data = {'count': 0, 'window_start': current_time}
        
        # Check if request is allowed
        limit = self.client.max_requests_per_minute
        if window_seconds != 60:
            # Adjust limit for different window sizes
            limit = int((limit * window_seconds) / 60)
        
        is_allowed = current_data['count'] < limit
        
        if is_allowed:
            # Increment counter
            current_data['count'] += 1
            
            # Calculate TTL for cache entry
            ttl = int(window_seconds - (current_time - current_data['window_start']))
            cache.set(cache_key, current_data, ttl)
            
            logger.debug(f"Rate limit check passed for {cache_key}: {current_data['count']}/{limit}")
        else:
            logger.warning(f"Rate limit exceeded for {cache_key}: {current_data['count']}/{limit}")
        
        # Calculate reset time
        reset_time = current_data['window_start'] + window_seconds
        
        return {
            'allowed': is_allowed,
            'current_count': current_data['count'],
            'limit': limit,
            'reset_time': reset_time,
            'window_seconds': window_seconds,
            'client_id': str(self.client.client_id),
            'client_type': self.client.client_type
        }
    
    def _get_cache_key(self, identifier: str = None) -> str:
        """
        Generate cache key for rate limiting.
        """
        if identifier:
            return f"{self.cache_prefix}:{identifier}"
        return self.cache_prefix
    
    def get_current_usage(self, identifier: str = None) -> Dict[str, Any]:
        """
        Get current rate limit usage without incrementing.
        """
        cache_key = self._get_cache_key(identifier)
        current_data = cache.get(cache_key, {'count': 0, 'window_start': time.time()})
        
        return {
            'current_count': current_data['count'],
            'limit': self.client.max_requests_per_minute,
            'window_start': current_data['window_start'],
            'client_id': str(self.client.client_id)
        }
    
    def reset_limit(self, identifier: str = None):
        """
        Reset rate limit for a specific identifier.
        """
        cache_key = self._get_cache_key(identifier)
        cache.delete(cache_key)
        logger.info(f"Rate limit reset for {cache_key}")


class AdvancedRateLimiter:
    """
    Advanced rate limiter with multiple time windows and burst protection.
    """
    
    def __init__(self, client: RegisteredClient):
        self.client = client
        self.cache_prefix = f"advanced_rate_limit:{client.client_id}"
        
        # Define multiple time windows for different limits
        self.windows = {
            'minute': {'seconds': 60, 'limit': client.max_requests_per_minute},
            'hour': {'seconds': 3600, 'limit': client.max_requests_per_minute * 60},
            'day': {'seconds': 86400, 'limit': client.max_requests_per_minute * 1440}
        }
    
    def is_allowed(self, identifier: str = None) -> Dict[str, Any]:
        """
        Check if request is allowed across multiple time windows.
        """
        results = {}
        overall_allowed = True
        
        for window_name, window_config in self.windows.items():
            cache_key = f"{self.cache_prefix}:{window_name}"
            if identifier:
                cache_key += f":{identifier}"
            
            # Check this window
            window_result = self._check_window(
                cache_key, 
                window_config['seconds'], 
                window_config['limit']
            )
            
            results[window_name] = window_result
            
            if not window_result['allowed']:
                overall_allowed = False
        
        # If allowed in all windows, increment all counters
        if overall_allowed:
            for window_name, window_config in self.windows.items():
                cache_key = f"{self.cache_prefix}:{window_name}"
                if identifier:
                    cache_key += f":{identifier}"
                self._increment_counter(cache_key, window_config['seconds'])
        
        return {
            'allowed': overall_allowed,
            'windows': results,
            'client_id': str(self.client.client_id),
            'client_type': self.client.client_type
        }
    
    def _check_window(self, cache_key: str, window_seconds: int, limit: int) -> Dict[str, Any]:
        """
        Check rate limit for a specific time window.
        """
        current_data = cache.get(cache_key, {'count': 0, 'window_start': time.time()})
        current_time = time.time()
        
        # Reset window if expired
        if current_time - current_data['window_start'] >= window_seconds:
            current_data = {'count': 0, 'window_start': current_time}
        
        is_allowed = current_data['count'] < limit
        reset_time = current_data['window_start'] + window_seconds
        
        return {
            'allowed': is_allowed,
            'current_count': current_data['count'],
            'limit': limit,
            'reset_time': reset_time,
            'window_seconds': window_seconds
        }
    
    def _increment_counter(self, cache_key: str, window_seconds: int):
        """
        Increment counter for a specific window.
        """
        current_data = cache.get(cache_key, {'count': 0, 'window_start': time.time()})
        current_time = time.time()
        
        # Reset window if expired
        if current_time - current_data['window_start'] >= window_seconds:
            current_data = {'count': 1, 'window_start': current_time}
        else:
            current_data['count'] += 1
        
        ttl = int(window_seconds - (current_time - current_data['window_start']))
        cache.set(cache_key, current_data, ttl)


class RateLimitManager:
    """
    Manager class for handling rate limiting operations.
    """
    
    @staticmethod
    def check_client_rate_limit(client: RegisteredClient, identifier: str = None) -> Dict[str, Any]:
        """
        Check rate limit for a client.
        """
        limiter = ClientRateLimiter(client)
        return limiter.is_allowed(identifier)
    
    @staticmethod
    def check_advanced_rate_limit(client: RegisteredClient, identifier: str = None) -> Dict[str, Any]:
        """
        Check advanced rate limit with multiple windows.
        """
        limiter = AdvancedRateLimiter(client)
        return limiter.is_allowed(identifier)
    
    @staticmethod
    def get_rate_limit_headers(rate_limit_result: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate HTTP headers for rate limiting information.
        """
        if 'windows' in rate_limit_result:
            # Advanced rate limiting - use minute window for headers
            minute_window = rate_limit_result['windows']['minute']
            return {
                'X-RateLimit-Limit': str(minute_window['limit']),
                'X-RateLimit-Remaining': str(max(0, minute_window['limit'] - minute_window['current_count'])),
                'X-RateLimit-Reset': str(int(minute_window['reset_time'])),
                'X-RateLimit-Window': str(minute_window['window_seconds'])
            }
        else:
            # Simple rate limiting
            return {
                'X-RateLimit-Limit': str(rate_limit_result['limit']),
                'X-RateLimit-Remaining': str(max(0, rate_limit_result['limit'] - rate_limit_result['current_count'])),
                'X-RateLimit-Reset': str(int(rate_limit_result['reset_time'])),
                'X-RateLimit-Window': str(rate_limit_result['window_seconds'])
            }
    
    @staticmethod
    def reset_client_rate_limit(client: RegisteredClient, identifier: str = None):
        """
        Reset rate limit for a client.
        """
        limiter = ClientRateLimiter(client)
        limiter.reset_limit(identifier)
        
        # Also reset advanced rate limiter
        advanced_limiter = AdvancedRateLimiter(client)
        for window_name in advanced_limiter.windows.keys():
            cache_key = f"{advanced_limiter.cache_prefix}:{window_name}"
            if identifier:
                cache_key += f":{identifier}"
            cache.delete(cache_key)
    
    @staticmethod
    def get_client_usage_stats(client: RegisteredClient, identifier: str = None) -> Dict[str, Any]:
        """
        Get current usage statistics for a client.
        """
        limiter = ClientRateLimiter(client)
        usage = limiter.get_current_usage(identifier)
        
        advanced_limiter = AdvancedRateLimiter(client)
        advanced_usage = {}
        
        for window_name, window_config in advanced_limiter.windows.items():
            cache_key = f"{advanced_limiter.cache_prefix}:{window_name}"
            if identifier:
                cache_key += f":{identifier}"
            
            current_data = cache.get(cache_key, {'count': 0, 'window_start': time.time()})
            advanced_usage[window_name] = {
                'current_count': current_data['count'],
                'limit': window_config['limit'],
                'window_seconds': window_config['seconds']
            }
        
        return {
            'basic': usage,
            'advanced': advanced_usage,
            'client_id': str(client.client_id),
            'client_type': client.client_type
        }


def rate_limit_decorator(identifier_func=None):
    """
    Decorator to apply rate limiting to functions.
    
    Args:
        identifier_func: Function to extract identifier from arguments
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Extract client from context (assuming it's available)
            info = args[2] if len(args) > 2 else None  # GraphQL info object
            if hasattr(info, 'context') and hasattr(info.context, 'client'):
                client = info.context.client
                
                # Get identifier if function provided
                identifier = None
                if identifier_func:
                    identifier = identifier_func(*args, **kwargs)
                
                # Check rate limit
                rate_limit_result = RateLimitManager.check_client_rate_limit(client, identifier)
                
                if not rate_limit_result['allowed']:
                    from graphql import GraphQLError
                    raise GraphQLError(
                        f"Rate limit exceeded. Try again in {int(rate_limit_result['reset_time'] - time.time())} seconds.",
                        extensions={
                            "code": "RATE_LIMIT_EXCEEDED",
                            "rate_limit": rate_limit_result
                        }
                    )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator
