# AfyaFlow Auth Service

AfyaFlow Auth Service is a robust authentication and user management system built with Django. It provides a GraphQL API for user registration, login (including social login with Google), multi-factor authentication (MFA), and user profile management. 

## Features

*   **User Authentication:** Secure registration and login with email and password.
*   **JWT Support:** Uses JSON Web Tokens (JWT) for stateless authentication (access and refresh tokens).
*   **GraphQL API:** Modern and flexible API for all authentication and user management operations.
*   **Google OAuth 2.0:** Allows users to sign up and log in using their Google accounts.
*   **Multi-Factor Authentication (MFA):** Supports Time-based One-Time Passwords (TOTP) for enhanced security.
*   **Custom User Model:** Extends Django's user model with additional fields like MFA settings and account suspension status.
*   **Password Management:** Secure password hashing, change password functionality, and password validation.
*   **Profile Management:** Users can update their profile information (first name, last name).
*   **External Organization Service Integration:** Can fetch user context from an external organization service upon login.
*   **Dockerized:** Fully containerized with Docker and Docker Compose for easy testing setup and deployment.
*   **Static File Serving:** Uses WhiteNoise for efficient static file serving in production.
*   **CORS Configuration:** Handles Cross-Origin Resource Sharing.

## Prerequisites

*   [Docker](https://www.docker.com/get-started)
*   [Docker Compose](https://docs.docker.com/compose/install/)

## Setup and Installation

1.  **Clone the repository (if applicable):**
    ```bash
    # git clone <repository-url>
    # cd <repository-name>
    ```

2.  **Create an environment file:**
    Copy the example environment variables or create a new `.env` file in the project root. See the "Environment Variables" section below for required variables.
    ```bash
    # create .env manually
    ```

3.  **Update Environment Variables in `.env`:**
    You **must** set the following variables. Refer to `docker-compose.yml` and `afyaflow_auth/settings.py` for a comprehensive list and their usage.
    *   `DJANGO_SECRET_KEY`: A strong, unique secret key for Django.
    *   `JWT_SECRET_KEY`: A strong, unique secret key for JWT signing.
    *   `GOOGLE_OAUTH_CLIENT_ID`: Your Google OAuth 2.0 Client ID.
    *   `GOOGLE_OAUTH_CLIENT_SECRET`: Your Google OAuth 2.0 Client Secret.
    *   Other variables like database credentials (defaults are provided in `docker-compose.yml` but can be overridden).

4.  **Build and run the application using Docker Compose:**
    ```bash
    docker-compose up --build -d
    ```
    The `-d` flag runs the containers in detached mode.

The application should now be running.
*   GraphQL API: `http://localhost:8000/graphql` (with GraphiQL interface)
*   Django Admin: `http://localhost:8000/admin/`
*   Allauth endpoints: `http://localhost:8000/accounts/` (e.g., `http://localhost:8000/accounts/login/`, `http://localhost:8000/accounts/google/login/`)

5.  **Create a superuser for Django admin:**
    ```bash
    # Create a superuser interactively
    docker-compose exec auth_service python manage.py createsuperuser
    ```
    You will be prompted to enter:
    - Email address
    - First name (optional)
    - Last name (optional) 
    - Password
    - Password confirmation

    Make sure to use a strong password as this account will have full administrative access.


## Environment Variables

The following are some of the key environment variables used by the application. These are typically set in the `.env` file at the project root, which is then used by `docker-compose.yml`.

*   `DEBUG`: Set to `True` for development, `False` for production. (Default: `False`)
*   `DJANGO_SECRET_KEY`: **Required**. Django's secret key.
*   `JWT_SECRET_KEY`: **Required**. Secret key for JWT signing. Defaults to `DJANGO_SECRET_KEY` if not set.
*   `DB_NAME`: PostgreSQL database name. (Default: `afyaflow_auth`)
*   `DB_USER`: PostgreSQL database user. (Default: `afyaflow`)
*   `DB_PASSWORD`: PostgreSQL database password. (Default: `afyaflow_password`)
*   `DB_HOST`: Database host. (Default: `db` - the service name in `docker-compose.yml`)
*   `DB_PORT`: Database port. (Default: `5432`)
*   `ALLOWED_HOSTS`: Comma-separated list of allowed hostnames. (e.g., `localhost,127.0.0.1,yourdomain.com`)
*   `CORS_ALLOWED_ORIGINS`: Comma-separated list of origins allowed for CORS. (e.g., `http://localhost:3000,https://yourfrontend.com`)
*   `ORGANIZATION_SERVICE_URL`: URL of the external organization service.
*   `GOOGLE_OAUTH_CLIENT_ID`: **Required**. Your Google OAuth 2.0 Client ID.
*   `GOOGLE_OAUTH_CLIENT_SECRET`: **Required**. Your Google OAuth 2.0 Client Secret.
*   `JWT_ACCESS_TOKEN_LIFETIME`: Lifetime of access tokens in minutes. (Default: 30)
*   `JWT_REFRESH_TOKEN_LIFETIME`: Lifetime of refresh tokens in minutes. (Default: 1440, i.e., 24 hours)

Refer to `docker-compose.yml` and `afyaflow_auth/settings.py` for defaults and more details.

## API Overview

The primary API is a GraphQL API accessible at `/graphql`. It includes a GraphiQL interface in debug mode for easy exploration and testing of queries and mutations.

Key GraphQL operations include:
*   User registration and login
*   Refreshing JWT tokens
*   User logout
*   Profile updates
*   Password changes
*   MFA setup, verification, and disabling
*   Login/registration with Google

For detailed API documentation, refer to `apiDocumentation.md`.

## Running the Application

Once the Docker containers are running (using `docker-compose up`), the application will be accessible:

*   **GraphQL API & GraphiQL IDE:** `http://localhost:8000/graphql`
*   **Django Admin Interface:** `http://localhost:8000/admin/`
    *   You'll need to create a superuser first:
        ```bash
        docker-compose exec auth_service python manage.py createsuperuser
        ```
*   **Allauth URLs:** `http://localhost:8000/accounts/` (e.g., for Google login initiation, password resets if configured through Allauth templates).
