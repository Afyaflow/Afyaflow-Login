release: python manage.py migrate && python manage.py load_service_accounts --force
web: gunicorn afyaflow_auth.wsgi:application --log-file - --log-level info --workers 2 --timeout 120