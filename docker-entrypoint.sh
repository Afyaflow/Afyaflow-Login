#!/bin/sh

# Debugging: Print environment for troubleshooting (sanitized)
echo "==== DEBUGGING ENVIRONMENT VARIABLES ===="
if [ -n "$DATABASE_URL" ]; then
  echo "DATABASE_URL is set (value hidden for security)"
else 
  echo "WARNING: DATABASE_URL is NOT set!"
fi

echo "DJANGO_SETTINGS_MODULE=$DJANGO_SETTINGS_MODULE"
echo "PYTHONPATH=$PYTHONPATH"
echo "RAILWAY_PUBLIC_DOMAIN=$RAILWAY_PUBLIC_DOMAIN"
echo "ALLOWED_HOSTS=$ALLOWED_HOSTS"
echo "======================================"

# Ensure DJANGO_SETTINGS_MODULE is set
if [ -z "$DJANGO_SETTINGS_MODULE" ]; then
  echo "DJANGO_SETTINGS_MODULE is not set! Setting it to afyaflow_auth.settings"
  export DJANGO_SETTINGS_MODULE=afyaflow_auth.settings
fi

# Check if Gunicorn will be able to find the wsgi.py file
echo "Checking for WSGI file..."
if [ -f /app/afyaflow_auth/wsgi.py ]; then
  echo "WSGI file exists and is accessible"
else
  echo "ERROR: WSGI file not found at /app/afyaflow_auth/wsgi.py"
  ls -la /app
  ls -la /app/afyaflow_auth
fi

# Debugging: Try connecting to the database using psql (will fail gracefully if not possible)
if [ -n "$DATABASE_URL" ]; then
  echo "Attempting to connect to database..."
  if command -v psql > /dev/null; then
    # Extract DB info from DATABASE_URL
    DB_HOST=$(echo $DATABASE_URL | sed -E 's/^postgres:\/\/[^:]+:[^@]+@([^:]+):.*/\1/')
    DB_PORT=$(echo $DATABASE_URL | sed -E 's/^postgres:\/\/[^:]+:[^@]+@[^:]+:([0-9]+)\/.*/\1/')
    echo "Testing connection to $DB_HOST:$DB_PORT..."
    nc -z -w5 $DB_HOST $DB_PORT
    if [ $? -eq 0 ]; then
      echo "Connection successful!"
    else
      echo "Connection failed!"
    fi
  else
    echo "psql not available for testing"
  fi
fi

echo "Applying database migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput --clear

# Create cache table for enhanced authentication features
echo "Setting up cache table for enhanced authentication..."
python manage.py createcachetable || echo "Cache table already exists or using Redis"

# Create default user roles for enhanced authentication
echo "Setting up default user roles for enhanced authentication..."
python -c "
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'afyaflow_auth.settings')
import django
django.setup()
from users.models import UserRole

# Define default roles
roles = [
    {
        'name': 'PATIENT',
        'description': 'Patient role for healthcare consumers',
        'permissions': [
            'view_own_profile',
            'update_own_profile',
            'view_own_medical_records',
            'access_patient_apps'
        ]
    },
    {
        'name': 'PROVIDER',
        'description': 'Healthcare provider role',
        'permissions': [
            'view_own_profile',
            'update_own_profile',
            'view_patient_records',
            'create_medical_records',
            'update_medical_records',
            'access_provider_apps',
            'manage_organization_patients'
        ]
    },
    {
        'name': 'ADMIN',
        'description': 'System administrator role',
        'permissions': [
            'view_all_users',
            'manage_users',
            'manage_organizations',
            'view_system_logs',
            'manage_system_settings',
            'access_admin_interface'
        ]
    }
]

# Create roles if they don't exist
for role_data in roles:
    role, created = UserRole.objects.get_or_create(
        name=role_data['name'],
        defaults=role_data
    )
    if created:
        print(f'✅ Created role: {role.name}')
    else:
        print(f'ℹ️ Role already exists: {role.name}')

print('User roles setup completed!')
"

# Create a test admin user if it doesn't exist
echo "Checking if we need to create a test admin user..."
python -c "
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'afyaflow_auth.settings')
import django
django.setup()
from users.models import User, UserRole
from users.role_management import RoleManager

if not User.objects.filter(email='admin@example.com').exists():
    print('Creating admin user...')
    admin_user = User.objects.create_superuser('admin@example.com', 'adminpassword123')

    # Assign ADMIN role to the admin user
    try:
        role_manager = RoleManager(admin_user)
        role_manager.assign_role('ADMIN', reason='Initial admin user setup')
        print('✅ Admin user created and ADMIN role assigned!')
    except Exception as e:
        print(f'⚠️ Admin user created but role assignment failed: {e}')
else:
    print('ℹ️ Admin user already exists')
"

# Enhanced Authentication System Status
echo "==== ENHANCED AUTHENTICATION STATUS ===="
echo "CLIENT_AUTH_ENABLED: ${CLIENT_AUTH_ENABLED:-false}"
echo "SECURITY_MONITORING_ENABLED: ${SECURITY_MONITORING_ENABLED:-false}"
echo "CLIENT_RATE_LIMITING_ENABLED: ${CLIENT_RATE_LIMITING_ENABLED:-false}"
echo "EMAIL_SERVICE_URL: ${EMAIL_SERVICE_URL:-not set}"
if [ -n "$REDIS_URL" ]; then
  echo "REDIS_URL: configured (using Redis cache)"
else
  echo "REDIS_URL: not set (using database cache)"
fi
echo "=========================================="

# Determine the port number (default to 8000 if not provided)
PORT=${PORT:-8000}
echo "PORT is set to: $PORT"
echo "Using address: 0.0.0.0:$PORT for binding"

# Check if any arguments were passed to the script
if [ $# -eq 0 ]; then
    echo "No command specified, running gunicorn by default..."
    echo "Starting gunicorn on port $PORT with command: gunicorn --workers=2 --timeout=120 --bind=0.0.0.0:$PORT afyaflow_auth.wsgi:application --log-file=-"
    
    # Add an explicit print statement at the end to confirm we're still running
    exec gunicorn --workers=2 --timeout=120 --bind=0.0.0.0:$PORT afyaflow_auth.wsgi:application --log-file=- --access-logfile=- --error-logfile=- --capture-output
else
    echo "Starting web server with command: $@"
    exec "$@"
fi 