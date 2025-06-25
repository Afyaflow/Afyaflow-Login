from .settings import *
import os

# Override debug setting
DEBUG = False

# Enhanced Security settings
SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'True').lower() in ('true', '1', 't')
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SAMESITE = 'Strict'
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Production Security Configuration
MAX_AUTH_ATTEMPTS_PER_IP = int(os.environ.get('MAX_AUTH_ATTEMPTS_PER_IP', '5'))  # Stricter in production
AUTH_LOCKOUT_DURATION_MINUTES = int(os.environ.get('AUTH_LOCKOUT_DURATION_MINUTES', '30'))  # Longer lockout
GRAPHQL_MAX_QUERY_DEPTH = int(os.environ.get('GRAPHQL_MAX_QUERY_DEPTH', '8'))  # Stricter depth limit
GRAPHQL_MAX_QUERY_COMPLEXITY = int(os.environ.get('GRAPHQL_MAX_QUERY_COMPLEXITY', '500'))  # Lower complexity limit

# Disable GraphQL introspection in production
GRAPHENE = {
    'SCHEMA': 'afyaflow_auth.schema.schema',
    'MIDDLEWARE': [
        'users.graphql.middleware.CombinedSecurityMiddleware',
    ],
}

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
} 