import os
import dj_database_url
from pathlib import Path
from dotenv import load_dotenv

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
default_allowed = ['127.0.0.1', 'localhost', '.railway.app']
if railway_domain:
    default_allowed.append(railway_domain)

ALLOWED_HOSTS = default_allowed + [host for host in os.getenv('ALLOWED_HOSTS', '').split(',') if host]
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
    'allauth.socialaccount.providers.google', # For Google OAuth
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
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
        'DIRS': [],
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

# Graphene-Django settings
GRAPHENE = {
    'SCHEMA': 'afyaflow_auth.schema.schema'  # Path to your main GraphQL schema
}

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom user model
AUTH_USER_MODEL = 'users.User'

AUTHENTICATION_BACKENDS = [
    # Needed to login by username in Django admin, regardless of `allauth`
    'django.contrib.auth.backends.ModelBackend',
    # `allauth` specific authentication methods, such as login by e-mail
    'allauth.account.auth_backends.AuthenticationBackend',
]

SITE_ID = 1

# Allauth settings
ACCOUNT_LOGIN_METHODS = ['email'] # 
ACCOUNT_SIGNUP_FIELDS = ['email'] # For programmatic use
ACCOUNT_EMAIL_VERIFICATION = 'optional' 
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True # Logs user in after email confirmation
ACCOUNT_LOGIN_ON_PASSWORD_RESET = True # Logs user in after password reset
# LOGIN_REDIRECT_URL = '/'  # Or frontend URL where user is redirected after login
# ACCOUNT_LOGOUT_REDIRECT_URL = '/'
SOCIALACCOUNT_ADAPTER = 'allauth.socialaccount.adapter.DefaultSocialAccountAdapter'
ACCOUNT_ADAPTER = 'allauth.account.adapter.DefaultAccountAdapter'
# Ensure our user model's email field is used as the username
ACCOUNT_USER_MODEL_USERNAME_FIELD = None # We use email, so no username field
ACCOUNT_USER_MODEL_EMAIL_FIELD = 'email'

SOCIALACCOUNT_PROVIDERS = {
    'google': {
        
        'APP': {
            'client_id': os.getenv('GOOGLE_OAUTH_CLIENT_ID'),
            'secret': os.getenv('GOOGLE_OAUTH_CLIENT_SECRET'),
            'key': ''
        },
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
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

# JWT Settings
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_LIFETIME = 30  # minutes
JWT_REFRESH_TOKEN_LIFETIME = 1440  # minutes (24 hours)
JWT_OCT_LIFETIME = 30 # minutes, lifetime for the organization context token

# CORS settings
CORS_ALLOW_ALL_ORIGINS = DEBUG  # Only for development
cors_origins_str = os.getenv('CORS_ALLOWED_ORIGINS', '')
CORS_ALLOWED_ORIGINS = [origin for origin in cors_origins_str.split(',') if origin] if not DEBUG else []

# Organization Service settings
ORGANIZATION_SERVICE_URL = os.getenv('ORGANIZATION_SERVICE_URL')
INTERNAL_SERVICE_TOKEN = os.getenv('INTERNAL_SERVICE_TOKEN')

# Google OAuth Client ID
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID') 

# Communication Service URL
COMMUNICATION_SERVICE_URL = os.getenv('COMMUNICATION_SERVICE_URL') 
