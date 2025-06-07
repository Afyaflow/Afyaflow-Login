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

# Create a test admin user if it doesn't exist
echo "Checking if we need to create a test admin user..."
python -c "
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'afyaflow_auth.settings')
import django
django.setup()
from users.models import User
if not User.objects.filter(email='admin@example.com').exists():
    print('Creating admin user...')
    User.objects.create_superuser('admin@example.com', 'adminpassword123')
    print('Admin user created!')
else:
    print('Admin user already exists')
"

# Determine the port number (default to 8000 if not provided)
PORT=${PORT:-8000}
echo "PORT is set to: $PORT"

# Check if any arguments were passed to the script
if [ $# -eq 0 ]; then
    echo "No command specified, running gunicorn by default..."
    echo "Starting gunicorn on port $PORT"
    exec gunicorn --workers=2 --timeout=120 --bind=0.0.0.0:$PORT afyaflow_auth.wsgi:application --log-file=-
else
    echo "Starting web server with command: $@"
    exec "$@"
fi 