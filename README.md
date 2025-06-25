# AfyaFlow Auth Service

A comprehensive authentication and user management service built with Django and GraphQL, providing secure user registration, multi-factor authentication, social login, and complete profile management.

## 🚀 Features

### Core Authentication
- **Email/Password Registration & Login** with email verification
- **Social Authentication** (Google, Microsoft, LinkedIn)
- **JWT Token Management** (Access tokens, Refresh tokens, Organization-scoped tokens)
- **Password Reset** with OTP verification

### Multi-Factor Authentication (MFA)
- **TOTP (Time-based OTP)** - Compatible with Google Authenticator, Authy, 1Password
- **SMS MFA** - Send verification codes via SMS
- **Email MFA** - Send verification codes via email
- **Flexible MFA Setup** - Users can enable multiple MFA methods

### Phone Number Management
- **Add & Verify Phone Numbers** - Complete phone number lifecycle management
- **Update Phone Numbers** - Change phone numbers with automatic re-verification
- **Remove Phone Numbers** - Secure removal with password confirmation
- **SMS Integration** - Phone numbers required for SMS MFA

### Profile Management
- **Update Profile Information** - Change names and personal details (firstName/lastName required)
- **Password Management** - Secure password changes
- **Account Status** - Email and phone verification status
- **MFA Status** - View and manage enabled MFA methods

## 🏗️ Architecture

### Technology Stack
- **Backend**: Django 5.2+ with Python 3.9+
- **API**: GraphQL with Graphene-Django
- **Database**: PostgreSQL (configurable)
- **Authentication**: JWT tokens with refresh mechanism
- **Social Auth**: Django Allauth integration
- **Communication**: Email and SMS services

### Key Components
- **User Model**: Extended Django user with MFA and verification fields
- **GraphQL API**: Complete mutation and query interface
- **OTP System**: Secure one-time password generation and verification
- **Token Management**: JWT access and refresh token handling
- **Communication Client**: Email and SMS delivery services

## 🚦 Quick Start

### Prerequisites
- Python 3.9+
- PostgreSQL (or SQLite for development)
- Redis (for caching, optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd auth-service
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Database Setup**
   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```

6. **Run Development Server**
   ```bash
   python manage.py runserver
   ```

7. **Access GraphQL Interface**
   - GraphiQL: http://localhost:8000/graphql
   - Admin: http://localhost:8000/admin

## ⚙️ Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/afyaflow_auth
# or for SQLite: DATABASE_URL=sqlite:///db.sqlite3

# Security
SECRET_KEY=your-secret-key-here
DEBUG=True  # Set to False in production
ALLOWED_HOSTS=localhost,127.0.0.1

# JWT Configuration
JWT_ACCESS_TOKEN_LIFETIME=30  # minutes
JWT_REFRESH_TOKEN_LIFETIME=7  # days

# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# SMS Configuration (Twilio example)
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=+1234567890

# Social Authentication
GOOGLE_OAUTH2_CLIENT_ID=your-google-client-id
GOOGLE_OAUTH2_CLIENT_SECRET=your-google-client-secret

MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret

LINKEDIN_CLIENT_ID=your-linkedin-client-id
LINKEDIN_CLIENT_SECRET=your-linkedin-client-secret

# Organization Service (if using microservices)
ORGANIZATION_SERVICE_URL=http://localhost:8001
INTERNAL_SERVICE_TOKEN=your-internal-service-token
```

### Social Authentication Setup

#### Google OAuth2
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth2 credentials
5. Add authorized redirect URIs

#### Microsoft OAuth2
1. Go to [Azure Portal](https://portal.azure.com/)
2. Register a new application
3. Configure authentication settings
4. Add redirect URIs

#### LinkedIn OAuth2
1. Go to [LinkedIn Developer Portal](https://developer.linkedin.com/)
2. Create a new application
3. Configure OAuth2 settings
4. Add authorized redirect URLs

## 📚 API Usage

### GraphQL Endpoint
- **URL**: `/graphql`
- **Method**: POST
- **Content-Type**: application/json

### Authentication
Include JWT token in Authorization header:
```
Authorization: Bearer <your-access-token>
```

### Key API Features

#### User Registration (firstName/lastName Required)
```graphql
mutation {
  register(
    email: "user@example.com"
    password: "SecurePassword123!"
    passwordConfirm: "SecurePassword123!"
    firstName: "John"    # Required
    lastName: "Doe"      # Required
  ) {
    authPayload {
      user { id email firstName lastName emailVerified }
      accessToken
      refreshToken
    }
    errors
  }
}
```

#### Complete Phone Number Management
```graphql
# Add phone number
mutation {
  addPhoneNumber(phoneNumber: "+1234567890") {
    ok
    message
    errors
  }
}

# Update phone number
mutation {
  updatePhoneNumber(phoneNumber: "+1987654321") {
    ok
    message
    errors
  }
}

# Remove phone number (requires password)
mutation {
  removePhoneNumber(password: "current_password") {
    ok
    user { phoneNumber smsMfaEnabled }
    errors
  }
}
```

#### Multi-Factor Authentication
```graphql
# Setup TOTP MFA
mutation {
  initiateTotpSetup {
    qrCodeImage  # Base64 encoded QR code
    mfaSecret    # Manual entry secret
    errors
  }
}

# Enable SMS MFA (requires verified phone)
mutation {
  initiateSmsMfaSetup {
    ok
    message
  }
}
```

## 🧪 Testing

### Run Tests
```bash
# Run all tests
python manage.py test

# Run specific test module
python manage.py test users.tests.test_models

# Run with coverage
coverage run --source='.' manage.py test
coverage report
coverage html  # Generate HTML report
```

### Test Categories
- **Model Tests**: User model and relationships
- **GraphQL Tests**: Mutation and query functionality
- **Authentication Tests**: Login, registration, MFA flows
- **Integration Tests**: End-to-end user journeys

## 🚀 Deployment

### Production Checklist
- [ ] Set `DEBUG=False`
- [ ] Configure production database
- [ ] Set up proper email service
- [ ] Configure SMS service
- [ ] Set up social auth credentials
- [ ] Configure HTTPS
- [ ] Set up monitoring and logging
- [ ] Configure backup strategy

### Docker Deployment
```dockerfile
# Dockerfile example
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN python manage.py collectstatic --noinput

EXPOSE 8000
CMD ["gunicorn", "afyaflow_auth.wsgi:application", "--bind", "0.0.0.0:8000"]
```

### Environment-Specific Settings
- **Development**: SQLite, debug mode, local email backend
- **Staging**: PostgreSQL, debug off, real email/SMS services
- **Production**: PostgreSQL, all security features, monitoring

## 📖 Documentation

- **[API Documentation](authServiceApiDocumentation.md)** - Complete GraphQL API reference
- **[Architecture Guide](docs/architecture.md)** - System design and components
- **[Security Guide](docs/security.md)** - Security best practices
- **[Deployment Guide](docs/deployment.md)** - Production deployment instructions

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Write tests for new features
- Update documentation
- Use meaningful commit messages

## Support

- **Documentation**: Check the docs folder for detailed guides
- **Issues**: Report bugs and request features via GitHub Issues
- **API Reference**: Use GraphiQL interface for interactive API exploration
- **Email Verification**: Consistent handling across all authentication methods
- **Phone Management**: Complete lifecycle with security features


## 🔧 Key Features Highlights

### Security Features
- **Required Names**: firstName and lastName mandatory for all registrations
- **Email Verification Consistency**: Synchronized between User and EmailAddress models
- **Phone Number Security**: Password-protected removal, format validation
- **MFA Integration**: Automatic SMS MFA management during phone changes
- **Token Security**: JWT with refresh mechanism and organization scoping

### User Experience
- **Seamless Phone Updates**: Change numbers without losing account access
- **Multiple MFA Options**: TOTP, SMS, and Email MFA support
- **Clear Error Messages**: Comprehensive validation and user feedback
- **Social Login Integration**: Automatic email verification for social accounts
- **Profile Management**: Easy name and contact information updates

### Developer Experience
- **GraphQL API**: Complete, well-documented API with GraphiQL interface
- **Comprehensive Testing**: Model, GraphQL, and integration tests
- **Easy Configuration**: Environment-based configuration
- **Docker Ready**: Production-ready containerization
- **Extensible**: Modular design for easy feature additions

