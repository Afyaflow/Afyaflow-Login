"""
WSGI config for afyaflow_auth project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'afyaflow_auth.settings')

application = get_wsgi_application() 