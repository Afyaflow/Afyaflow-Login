#!/bin/sh

# Wait for database to be ready
echo "Waiting for PostgreSQL..."
while ! nc -z db 5432; do
    sleep 0.1
done
echo "PostgreSQL started"

# Make migrations for the users app first
python manage.py makemigrations users

# Apply migrations
python manage.py migrate users
python manage.py migrate

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Start server
python manage.py runserver 0.0.0.0:8000 