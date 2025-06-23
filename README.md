# AfyaFlow Auth Service

## Overview

The AfyaFlow Auth Service is a centralized, standalone Django application responsible for all user authentication, authorization, and management within the AfyaFlow ecosystem. It exposes a federated GraphQL API for seamless integration with other services, including the frontend application and the Organizations service.

---

## Core Features

-   **User Accounts:** Standard email/password registration and login.
-   **Secure Password Management:** Robust, OTP-based password reset flow and secure password change functionality.
-   **Multi-Factor Authentication (MFA):** Supports a consistent `initiate` -> `verify` -> `disable` flow for multiple MFA methods:
    -   TOTP (Authenticator Apps like Google Authenticator)
    -   Email OTP
    -   SMS OTP
-   **Contact Verification:** Flows for verifying user email addresses and phone numbers.
-   **Social Login:** Secure login and registration via major providers, fully integrated with the MFA system. Powered by `django-allauth`.
    -   Google
    -   Microsoft
    -   LinkedIn
-   **Federated Authorization:** Issues Organization Context Tokens (OCTs) for role-based access control in other services.

---

## Local Development Setup

### Prerequisites

-   Python 3.11+
-   A Python virtual environment tool (e.g., `venv`)
-   A running PostgreSQL instance

### 1. Installation

```bash
# Clone the repository
git clone <repository_url>
cd auth-service

# Create and activate a virtual environment
python -m venv venv
# On Windows
# .\\venv\\Scripts\\activate
# On macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

This project uses environment variables for configuration. Create a `.env` file in the project root. 

Key variables to configure:
-   `SECRET_KEY`: Your Django secret key.
-   `DATABASE_URL`: The connection string for your PostgreSQL database (e.g., `postgres://user:password@localhost:5432/afyaflow_auth_db`).
-   `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, etc.: Credentials for your SMTP service for sending emails.
-   `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_SECRET`: Credentials for Google social login.
-   `MICROSOFT_GRAPH_CLIENT_ID`, `MICROSOFT_GRAPH_SECRET`: Credentials for Microsoft social login.
-   `LINKEDIN_OAUTH2_CLIENT_ID`, `LINKEDIN_OAUTH2_SECRET`: Credentials for LinkedIn social login.

### 3. Database Setup

Ensure your PostgreSQL server is running and you have created a database for the service.

```bash
# Apply the database schema
python manage.py migrate
```

### 4. Running the Server

```bash
# Start the local development server
python manage.py runserver
```
The GraphQL API will be available at `http://127.0.0.1:8000/graphql`.

---

## GraphQL API Reference

### User Authentication & Registration

#### `register`
Creates a new user account. On success, it sends a verification OTP to the user's email.
-   **Arguments:** `email`, `password`, `passwordConfirm`, `firstName`, `lastName`
-   **Returns:** `AuthPayloadType` with tokens and `user.emailVerified: false`.

#### `login`
Logs a user in.
-   **Arguments:** `email`, `password`
-   **Returns:** `AuthPayloadType`.
    -   **If no MFA:** Returns user object and access/refresh tokens.
    -   **If MFA is enabled:** Returns user object, `mfaRequired: true`, `mfaToken`, and `enabledMfaMethods`. Tokens are `null`.

#### `verifyMfa`
Completes the second step of an MFA login.
-   **Arguments:** `mfaToken` (from `login` response), `otpCode`
-   **Returns:** `AuthPayloadType` with tokens.

#### `loginWithGoogle`
Logs in or registers a user with their Google account.
-   **Arguments:** `accessToken` (from Google Sign-In SDK)
-   **Returns:** `AuthPayloadType` (may require MFA verification).

#### `loginWithMicrosoft`
Logs in or registers a user with their Microsoft account.
-   **Arguments:** `accessToken` (from MSAL)
-   **Returns:** `AuthPayloadType` (may require MFA verification).

#### `loginWithLinkedin`
Logs in or registers a user with their LinkedIn account.
-   **Arguments:** `accessToken` (from LinkedIn OAuth flow)
-   **Returns:** `AuthPayloadType` (may require MFA verification).

#### `refreshToken`
Issues a new access token.
-   **Arguments:** `refreshToken`
-   **Returns:** A new `accessToken`.

#### `logout`
Invalidates the user's refresh token.
-   **Arguments:** `refreshToken`

### Password Management

#### `changePassword`
Allows a logged-in user to change their password.
-   **Arguments:** `oldPassword`, `newPassword`, `newPasswordConfirm`

#### Forgot Password Flow (2 Steps)

1.  **`initiatePasswordReset`**
    -   Sends a 6-digit OTP to the user's specified contact channel.
    -   **Arguments:** `emailOrPhone` (can be an email address or a phone number).
2.  **`resetPasswordWithOtp`**
    -   Verifies the OTP and sets the new password.
    -   **Arguments:** `emailOrPhone` (from Step 1), `otpCode`, `newPassword`, `newPasswordConfirm`

### Email & Phone Verification

#### `resendVerificationEmail`
Sends a new verification OTP to the logged-in user's email.

#### `verifyEmail`
Verifies the OTP to mark the user's email as verified.
-   **Arguments:** `otpCode`

#### `addPhoneNumber`
Adds a phone number to a user's account and sends a verification OTP via SMS.
-   **Arguments:** `phoneNumber` (must be in E.164 format, e.g., `+254790787787`).

#### `verifyPhoneNumber`
Verifies the OTP to mark the user's phone number as verified.
-   **Arguments:** `otpCode`

### Multi-Factor Authentication (MFA) Management

All MFA methods follow a consistent `initiate` -> `verify` -> `disable` flow.

#### TOTP (Authenticator App)
1.  **`initiateTotpSetup`**: Returns a provisioning URI and a Base64 QR code image for the user to scan.
2.  **`verifyTotpSetup`**: Confirms the setup by validating an OTP from the app. (Arg: `otpCode`)
3.  **`disableTotp`**: Disables TOTP by validating a final OTP from the app. (Arg: `otpCode`)

#### Email MFA
1.  **`initiateEmailMfaSetup`**: Sends an OTP to the user's verified email.
2.  **`verifyEmailMfaSetup`**: Validates the OTP to enable Email MFA. (Arg: `otpCode`)
3.  **`disableEmailMfa`**: Disables Email MFA after validating the user's current password. (Arg: `password`)

#### SMS MFA
1.  **`initiateSmsMfaSetup`**: Sends an OTP to the user's verified phone number.
2.  **`verifySmsMfaSetup`**: Validates the OTP to enable SMS MFA. (Arg: `otpCode`)
3.  **`disableSmsMfa`**: Disables SMS MFA after validating the user's current password. (Arg: `password`)
