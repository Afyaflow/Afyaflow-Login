import os
import sys
import logging
import dj_database_url
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'django-insecure-default-key-change-this')


DEBUG = os.getenv('DEBUG', 'False') == 'True'

# Print debugging info
railway_domain = os.getenv('RAILWAY_PUBLIC_DOMAIN', '')
if railway_domain:
    print(f"RAILWAY_PUBLIC_DOMAIN is: {railway_domain}")

# Always include common local hosts, railway domain, and any domains from ALLOWED_HOSTS env var
default_allowed = ['127.0.0.1', 'localhost', '.railway.app', 'testserver']
if railway_domain:
    default_allowed.append(railway_domain)

ALLOWED_HOSTS = default_allowed + [host for host in os.getenv('ALLOWED_HOSTS', '').split(',') if host]

# Add testserver for Django test client
if 'test' in sys.argv or 'pytest' in sys.modules:
    ALLOWED_HOSTS.append('testserver')

print(f"ALLOWED_HOSTS: {ALLOWED_HOSTS}")

# A list of trusted origins for unsafe requests (e.g., POST).
# This is a security measure to prevent CSRF attacks.
csrf_origins_str = os.getenv('CSRF_TRUSTED_ORIGINS', '')
csrf_origins = []

# Add origins from environment variable if any
for origin in csrf_origins_str.split(','):
    if origin.strip():
        csrf_origins.append(origin.strip())

# Always include Railway domains for CSRF protection
if railway_domain:
    csrf_origins.append(f"https://{railway_domain}")

# Always allow Railway domains
csrf_origins.append("https://*.railway.app")

CSRF_TRUSTED_ORIGINS = csrf_origins
print(f"CSRF_TRUSTED_ORIGINS: {CSRF_TRUSTED_ORIGINS}")

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'whitenoise.runserver_nostatic', # Should be placed after staticfiles
    'django.contrib.staticfiles',
    'django.contrib.sites',
    # Third party apps
    'rest_framework',
    'corsheaders',
    'graphene_django',
    # Local apps
    'users',
    # Allauth apps
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.microsoft',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'users.security_middleware.RateLimitMiddleware',
    'users.security_middleware.SecurityHeadersMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'users.auth_middleware.GraphQLJWTMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'afyaflow_auth.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'afyaflow_auth.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'afyaflow_auth'),
        'USER': os.getenv('DB_USER', 'postgres'),
        'PASSWORD': os.getenv('DB_PASSWORD', ''),
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}

# In production, Railway provides a DATABASE_URL environment variable.
if 'DATABASE_URL' in os.environ:
    DATABASES['default'] = dj_database_url.config(conn_max_age=600, ssl_require=True)

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# Graphene-Django settings with security enhancements
GRAPHENE = {
    'SCHEMA': 'afyaflow_auth.schema.schema',  # Path to your main GraphQL schema
}

# Add security middleware only in production or when explicitly enabled
if not DEBUG or os.getenv('ENABLE_GRAPHQL_SECURITY_MIDDLEWARE', 'False').lower() in ('true', '1', 't'):
    GRAPHENE['MIDDLEWARE'] = [
        'users.graphql.middleware.CombinedSecurityMiddleware',
    ]

# GraphQL Security Settings
GRAPHQL_MAX_QUERY_DEPTH = int(os.getenv('GRAPHQL_MAX_QUERY_DEPTH', '10'))
GRAPHQL_MAX_QUERY_COMPLEXITY = int(os.getenv('GRAPHQL_MAX_QUERY_COMPLEXITY', '1000'))

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom user model
AUTH_USER_MODEL = 'users.User'

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

# Site ID must match the ID in database
SITE_ID = 2  # Changed from 1 to match database site ID

# Allauth settings
ACCOUNT_LOGIN_METHODS = {'email'}  # Replaces ACCOUNT_AUTHENTICATION_METHOD
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*', 'password2*']  # Replaces ACCOUNT_EMAIL_REQUIRED and ACCOUNT_USERNAME_REQUIRED
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_EMAIL_VERIFICATION = 'mandatory'
ACCOUNT_EMAIL_SUBJECT_PREFIX = '[AfyaFlow] '
ACCOUNT_DEFAULT_HTTP_PROTOCOL = 'https'
ACCOUNT_ADAPTER = 'allauth.account.adapter.DefaultAccountAdapter'
SOCIALACCOUNT_ADAPTER = 'allauth.socialaccount.adapter.DefaultSocialAccountAdapter'
SOCIALACCOUNT_EMAIL_VERIFICATION = 'none'  # Since we verify through the provider
SOCIALACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_STORE_TOKENS = True
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
    },
    'microsoft': {
        'SCOPE': [
            'profile',
            'email',
            'openid',
        ],
    }
}

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'users.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10
}

# JWT Settings - Gateway Compliance with User-Type-Specific Secrets
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)  # Legacy fallback
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_LIFETIME = 30  # minutes
JWT_REFRESH_TOKEN_LIFETIME = 1440  # minutes (24 hours)
JWT_OCT_LIFETIME = 30 # minutes, lifetime for the organization context token
JWT_MFA_TOKEN_LIFETIME = 5 # minutes, for the two-step login flow

# Gateway Compliance: User-Type-Specific JWT Secrets
PROVIDER_AUTH_TOKEN_SECRET = os.getenv('PROVIDER_AUTH_TOKEN_SECRET')
PATIENT_AUTH_TOKEN_SECRET = os.getenv('PATIENT_AUTH_TOKEN_SECRET')
OPERATIONS_AUTH_TOKEN_SECRET = os.getenv('OPERATIONS_AUTH_TOKEN_SECRET')
ORG_CONTEXT_TOKEN_SECRET = os.getenv('ORG_CONTEXT_TOKEN_SECRET')

# Generate temporary secrets if not set (development only)
if not PROVIDER_AUTH_TOKEN_SECRET:
    import secrets
    PROVIDER_AUTH_TOKEN_SECRET = secrets.token_urlsafe(64)
    logger.warning("PROVIDER_AUTH_TOKEN_SECRET not set. Generated temporary key. Set for production!")

if not PATIENT_AUTH_TOKEN_SECRET:
    import secrets
    PATIENT_AUTH_TOKEN_SECRET = secrets.token_urlsafe(64)
    logger.warning("PATIENT_AUTH_TOKEN_SECRET not set. Generated temporary key. Set for production!")

if not OPERATIONS_AUTH_TOKEN_SECRET:
    import secrets
    OPERATIONS_AUTH_TOKEN_SECRET = secrets.token_urlsafe(64)
    logger.warning("OPERATIONS_AUTH_TOKEN_SECRET not set. Generated temporary key. Set for production!")

if not ORG_CONTEXT_TOKEN_SECRET:
    import secrets
    ORG_CONTEXT_TOKEN_SECRET = secrets.token_urlsafe(64)
    logger.warning("ORG_CONTEXT_TOKEN_SECRET not set. Generated temporary key. Set for production!")

# CORS settings
CORS_ALLOW_ALL_ORIGINS = DEBUG  # Only for development
cors_origins_str = os.getenv('CORS_ALLOWED_ORIGINS', '')
CORS_ALLOWED_ORIGINS = [origin for origin in cors_origins_str.split(',') if origin] if not DEBUG else []

# Additional CORS settings for GraphiQL in development
if DEBUG:
    CORS_ALLOW_CREDENTIALS = True
    CORS_ALLOWED_HEADERS = [
        'accept',
        'accept-encoding',
        'authorization',
        'content-type',
        'dnt',
        'origin',
        'user-agent',
        'x-csrftoken',
        'x-requested-with',
    ]

# Organization Service settings
ORGANIZATION_SERVICE_URL = os.getenv('ORGANIZATION_SERVICE_URL')
INTERNAL_SERVICE_TOKEN = os.getenv('INTERNAL_SERVICE_TOKEN')

# Email Service settings
EMAIL_SERVICE_URL = os.getenv('EMAIL_SERVICE_URL')

# Google OAuth Client ID
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID') 
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')

# Session settings for production
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_SECURE = not DEBUG  # Use secure cookies in production
CSRF_COOKIE_SECURE = not DEBUG     # Use secure CSRF cookies in production
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'

# Trust the "X-Forwarded-Proto" header from the reverse proxy (Railway)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True

# Security Configuration
MAX_AUTH_ATTEMPTS_PER_IP = int(os.getenv('MAX_AUTH_ATTEMPTS_PER_IP', '10'))
AUTH_LOCKOUT_DURATION_MINUTES = int(os.getenv('AUTH_LOCKOUT_DURATION_MINUTES', '15'))
ENABLE_AUTHENTICATION_LOGGING = os.getenv('ENABLE_AUTHENTICATION_LOGGING', 'True').lower() in ('true', '1', 't')

# JWT Security - Ensure separate secret key
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
if not JWT_SECRET_KEY:
    import secrets
    JWT_SECRET_KEY = secrets.token_urlsafe(64)
    logger.warning("JWT_SECRET_KEY not set in environment. Generated temporary key. Set JWT_SECRET_KEY for production!")

# Session Security Enhancement
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict' if not DEBUG else 'Lax'
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict' if not DEBUG else 'Lax'
