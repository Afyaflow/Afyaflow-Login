"""
WSGI config for afyaflow_auth project.
"""

import os
import sys

# Print debugging information
print("Starting WSGI application")
print(f"Python version: {sys.version}")
print(f"Python path: {sys.path}")
print(f"Working directory: {os.getcwd()}")

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'afyaflow_auth.settings')

try:
    application = get_wsgi_application()
    print("WSGI application initialized successfully")
except Exception as e:
    print(f"Error initializing WSGI application: {e}")
    raise 