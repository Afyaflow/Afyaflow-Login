release: python manage.py migrate
web: gunicorn afyaflow_auth.wsgi:application --log-file - --log-level debug 