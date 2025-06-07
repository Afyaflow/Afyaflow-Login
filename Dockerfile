
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH=/app

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Make directory for application code
RUN mkdir -p /app/afyaflow_auth /app/users

# Copy entrypoint script and make it executable (as root)
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

# Create a non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser


EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"] 