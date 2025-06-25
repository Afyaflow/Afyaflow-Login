# AfyaFlow Auth Service API Documentation (GraphQL)

This document provides comprehensive documentation for the AfyaFlow Auth Service GraphQL API. It includes all available queries, mutations, types, and examples for user authentication, multi-factor authentication, profile management, and social authentication.

---

## 🚀 Introduction

The AfyaFlow Auth Service provides a complete authentication and user management solution with the following features:

### Core Features
- **User Registration & Login** - Email/password authentication with email verification
- **Social Authentication** - Google, Microsoft, and LinkedIn OAuth2 integration
- **Multi-Factor Authentication (MFA)** - TOTP (Authenticator apps), SMS, and Email MFA
- **JWT Token Management** - Access tokens, refresh tokens, and organization-scoped tokens
- **Profile Management** - User profile updates, password changes, and account management
- **Phone Number Management** - Add and verify phone numbers for SMS MFA
- **Password Reset** - Secure password reset with OTP verification

### GraphQL Endpoint
- **URL**: `/graphql`
- **Development**: GraphiQL interface available at `/graphql` when `DEBUG=True`

---

## 🔐 Authentication & Authorization

### JWT Token System

The service uses a dual-token JWT system for authentication:

#### Access Tokens
- **Purpose**: Authenticate API requests
- **Lifetime**: 30 minutes (configurable)
- **Usage**: Include in `Authorization` header as `Bearer <token>`
- **Contains**: User ID, permissions, expiration

#### Refresh Tokens
- **Purpose**: Obtain new access tokens without re-authentication
- **Lifetime**: 7 days (configurable)
- **Storage**: Stored securely in database, can be revoked
- **Usage**: Use with `refreshToken` mutation

#### Organization Context Tokens (OCT)
- **Purpose**: Access organization-specific resources
- **Lifetime**: Same as access tokens
- **Usage**: Obtained via `getScopedAccessToken` mutation
- **Contains**: User permissions within specific organization

### Authentication Flow

```
1. User registers/logs in → Receives access + refresh tokens
2. Use access token for API requests
3. When access token expires → Use refresh token to get new access token
4. For organization operations → Get OCT with getScopedAccessToken
```

### Multi-Factor Authentication (MFA)

The service supports three MFA methods:

#### TOTP (Time-based One-Time Password)
- **Apps**: Google Authenticator, Authy, 1Password, etc.
- **Setup**: QR code or manual secret entry
- **Verification**: 6-digit time-based codes

#### SMS MFA
- **Requirement**: Verified phone number
- **Delivery**: SMS to registered phone number
- **Verification**: 6-digit codes

#### Email MFA
- **Delivery**: Email to registered email address
- **Verification**: 6-digit codes

### MFA Login Flow

When MFA is enabled, login becomes a two-step process:

```
1. login(email, password) → Returns mfaRequired: true, mfaToken
2. verifyMfa(mfaToken, otpCode) → Returns access + refresh tokens
```

---

## 🧩 Core GraphQL Types

### UserType

Represents a user in the AfyaFlow system.

```graphql
type User {
  id: UUID!
  email: String!
  firstName: String!
  lastName: String!
  isActive: Boolean!
  isStaff: Boolean!
  isSuperuser: Boolean!
  isSuspended: Boolean!
  dateJoined: DateTime!
  lastLogin: DateTime
  emailVerified: Boolean!
  phoneNumber: String
  phoneNumberVerified: Boolean!
  
  # MFA Status Fields
  totpMfaEnabled: Boolean!
  smsMfaEnabled: Boolean!
  emailMfaEnabled: Boolean!
}
```

### AuthPayloadType

Returned by authentication mutations (login, register, social auth).

```graphql
type AuthPayload {
  user: User
  accessToken: String
  refreshToken: String
  mfaRequired: Boolean!
  mfaToken: String
  enabledMfaMethods: [String]
  organizationMemberships: [OrganizationMembership]
}
```

### Error Handling

All mutations return an `errors: [String]` field. Always check this field:

```graphql
mutation SomeOperation {
  someOperation(input: "value") {
    # Success fields
    user { id email }
    # Always check for errors
    errors
  }
}
```

---

## ❓ GraphQL Queries

### me

Returns the profile of the currently authenticated user.

**Authentication**: Required (Bearer token)

```graphql
query GetCurrentUser {
  me {
    id
    email
    firstName
    lastName
    emailVerified
    phoneNumber
    phoneNumberVerified
    totpMfaEnabled
    smsMfaEnabled
    emailMfaEnabled
    dateJoined
    lastLogin
  }
}
```

---

## 🔄 Authentication Mutations

### register

Registers a new user and sends email verification OTP.

**Arguments:**
- `email: String!` - User's email address
- `password: String!` - Password (min 8 characters)
- `passwordConfirm: String!` - Password confirmation
- `firstName: String!` - User's first name (required)
- `lastName: String!` - User's last name (required)

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation RegisterUser {
  register(
    email: "user@example.com"
    password: "SecurePassword123!"
    passwordConfirm: "SecurePassword123!"
    firstName: "John"    # Required
    lastName: "Doe"      # Required
  ) {
    authPayload {
      user {
        id
        email
        firstName
        lastName
        emailVerified
      }
      accessToken
      refreshToken
    }
    errors
  }
}
```

### login

Authenticates a user with email and password.

**Arguments:**
- `email: String!` - User's email
- `password: String!` - User's password

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation LoginUser {
  login(email: "user@example.com", password: "password123") {
    authPayload {
      user { id email }
      accessToken
      refreshToken
      mfaRequired
      mfaToken
      enabledMfaMethods
    }
    errors
  }
}
```

### verifyMfa

Completes MFA verification during login.

**Arguments:**
- `mfaToken: String!` - Short-lived MFA token from login
- `otpCode: String!` - 6-digit OTP code

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation VerifyMFA {
  verifyMfa(mfaToken: "mfa_token_here", otpCode: "123456") {
    authPayload {
      user { id email }
      accessToken
      refreshToken
    }
    errors
  }
}
```

### refreshToken

Obtains a new access token using a refresh token.

**Arguments:**
- `refreshToken: String!` - Valid refresh token

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation RefreshAccessToken {
  refreshToken(refreshToken: "refresh_token_here") {
    authPayload {
      accessToken
      refreshToken
    }
    errors
  }
}
```

### logout

Invalidates a refresh token.

**Arguments:**
- `refreshToken: String!` - Refresh token to invalidate

**Returns:** `ok: Boolean`, `errors: [String]`

```graphql
mutation LogoutUser {
  logout(refreshToken: "refresh_token_here") {
    ok
    errors
  }
}
```

### getScopedAccessToken

Obtains an organization-scoped access token.

**Authentication**: Required

**Arguments:**
- `organizationId: String!` - Organization UUID

**Returns:** `ScopedAuthPayload`, `errors: [String]`

```graphql
mutation GetOrgToken {
  getScopedAccessToken(organizationId: "org-uuid-here") {
    accessToken
    organization { id name }
    permissions
    errors
  }
}
```

---

## 🌐 Social Authentication Mutations

### loginWithGoogle

Authenticates using Google OAuth2.

**Arguments:**
- `accessToken: String!` - Google OAuth2 access token
- `idToken: String` - Optional Google ID token

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation GoogleLogin {
  loginWithGoogle(accessToken: "google_access_token") {
    authPayload {
      user {
        id
        email
        firstName
        lastName
        emailVerified
      }
      accessToken
      refreshToken
      mfaRequired
    }
    errors
  }
}
```

### loginWithMicrosoft

Authenticates using Microsoft OAuth2.

**Arguments:**
- `accessToken: String!` - Microsoft OAuth2 access token
- `idToken: String` - Optional Microsoft ID token

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation MicrosoftLogin {
  loginWithMicrosoft(accessToken: "microsoft_access_token") {
    authPayload {
      user { id email firstName lastName }
      accessToken
      refreshToken
    }
    errors
  }
}
```

### loginWithLinkedin

Authenticates using LinkedIn OAuth2.

**Arguments:**
- `accessToken: String!` - LinkedIn OAuth2 access token
- `idToken: String` - Optional LinkedIn ID token

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation LinkedInLogin {
  loginWithLinkedin(accessToken: "linkedin_access_token") {
    authPayload {
      user { id email firstName lastName }
      accessToken
      refreshToken
    }
    errors
  }
}
```

---

## 👤 Profile Management Mutations

### updateProfile

Updates the authenticated user's profile information.

**Authentication**: Required

**Arguments:**
- `firstName: String` - Optional new first name
- `lastName: String` - Optional new last name

**Returns:** `User`, `errors: [String]`

```graphql
mutation UpdateUserProfile {
  updateProfile(firstName: "John", lastName: "Smith") {
    user {
      id
      email
      firstName
      lastName
      totpMfaEnabled
      smsMfaEnabled
      emailMfaEnabled
    }
    errors
  }
}
```

### changePassword

Changes the authenticated user's password.

**Authentication**: Required

**Arguments:**
- `oldPassword: String!` - Current password
- `newPassword: String!` - New password
- `newPasswordConfirm: String!` - New password confirmation

**Returns:** `ok: Boolean`, `errors: [String]`

```graphql
mutation ChangeUserPassword {
  changePassword(
    oldPassword: "current_password"
    newPassword: "new_secure_password"
    newPasswordConfirm: "new_secure_password"
  ) {
    ok
    errors
  }
}
```

### initiatePasswordReset

Initiates password reset by sending OTP to email or phone.

**Arguments:**
- `emailOrPhone: String!` - Email address or phone number

**Returns:** `ok: Boolean`, `message: String`

```graphql
mutation InitiateReset {
  initiatePasswordReset(emailOrPhone: "user@example.com") {
    ok
    message
  }
}
```

### resetPasswordWithOtp

Completes password reset using OTP verification.

**Arguments:**
- `emailOrPhone: String!` - Email or phone used for reset
- `otpCode: String!` - OTP code received
- `newPassword: String!` - New password
- `newPasswordConfirm: String!` - New password confirmation

**Returns:** `ok: Boolean`, `errors: [String]`

```graphql
mutation ResetPassword {
  resetPasswordWithOtp(
    emailOrPhone: "user@example.com"
    otpCode: "123456"
    newPassword: "new_password"
    newPasswordConfirm: "new_password"
  ) {
    ok
    errors
  }
}
```

---

## ✉️ Email Verification Mutations

### verifyEmail

Verifies user's email address using OTP.

**Authentication**: Required

**Arguments:**
- `otpCode: String!` - 6-digit OTP code from email

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation VerifyUserEmail {
  verifyEmail(otpCode: "123456") {
    authPayload {
      user {
        id
        email
        emailVerified
      }
    }
    errors
  }
}
```

### resendVerificationEmail

Resends email verification OTP.

**Authentication**: Required

**Returns:** `ok: Boolean`, `message: String`, `errors: [String]`

```graphql
mutation ResendVerification {
  resendVerificationEmail {
    ok
    message
    errors
  }
}
```

---

## 📱 Phone Number Management Mutations

### addPhoneNumber

Adds and verifies a phone number for the user.

**Authentication**: Required

**Arguments:**
- `phoneNumber: String!` - Phone number in international format

**Returns:** `ok: Boolean`, `message: String`, `errors: [String]`

```graphql
mutation AddPhone {
  addPhoneNumber(phoneNumber: "+1234567890") {
    ok
    message
    errors
  }
}
```

### verifyPhoneNumber

Verifies the phone number using OTP sent via SMS.

**Authentication**: Required

**Arguments:**
- `otpCode: String!` - 6-digit OTP code from SMS

**Returns:** `ok: Boolean`, `user: User`, `errors: [String]`

```graphql
mutation VerifyPhone {
  verifyPhoneNumber(otpCode: "123456") {
    ok
    user {
      phoneNumber
      phoneNumberVerified
    }
    errors
  }
}
```

### updatePhoneNumber

Updates the user's phone number and sends verification OTP to the new number.

**Authentication**: Required

**Arguments:**
- `phoneNumber: String!` - New phone number in international format

**Returns:** `ok: Boolean`, `message: String`, `errors: [String]`

**Note**: If SMS MFA was enabled with the old number, it will be automatically disabled until the new number is verified.

```graphql
mutation UpdatePhone {
  updatePhoneNumber(phoneNumber: "+1987654321") {
    ok
    message
    errors
  }
}
```

### removePhoneNumber

Removes the user's phone number and disables SMS MFA.

**Authentication**: Required

**Arguments:**
- `password: String!` - Current password for verification

**Returns:** `ok: Boolean`, `user: User`, `errors: [String]`

```graphql
mutation RemovePhone {
  removePhoneNumber(password: "current_password") {
    ok
    user {
      phoneNumber
      phoneNumberVerified
      smsMfaEnabled
    }
    errors
  }
}
```

### resendPhoneVerification

Resends the phone verification OTP to the current phone number.

**Authentication**: Required

**Returns:** `ok: Boolean`, `message: String`, `errors: [String]`

```graphql
mutation ResendPhoneOTP {
  resendPhoneVerification {
    ok
    message
    errors
  }
}
```

---

## 🔐 TOTP MFA Mutations

### initiateTotpSetup

Initiates TOTP MFA setup by generating QR code and secret.

**Authentication**: Required

**Returns:** `ok: Boolean`, `otpProvisioningUri: String`, `mfaSecret: String`, `qrCodeImage: String`, `errors: [String]`

```graphql
mutation SetupTOTP {
  initiateTotpSetup {
    ok
    otpProvisioningUri
    mfaSecret
    qrCodeImage  # Base64 encoded QR code PNG
    errors
  }
}
```

### verifyTotpSetup

Verifies and enables TOTP MFA.

**Authentication**: Required

**Arguments:**
- `otpCode: String!` - 6-digit code from authenticator app

**Returns:** `ok: Boolean`, `user: User`, `errors: [String]`

```graphql
mutation VerifyTOTPSetup {
  verifyTotpSetup(otpCode: "123456") {
    ok
    user {
      totpMfaEnabled
    }
    errors
  }
}
```

### disableTotp

Disables TOTP MFA for the user.

**Authentication**: Required

**Arguments:**
- `otpCode: String!` - Current TOTP code for verification

**Returns:** `ok: Boolean`, `user: User`, `errors: [String]`

```graphql
mutation DisableTOTP {
  disableTotp(otpCode: "123456") {
    ok
    user {
      totpMfaEnabled
    }
    errors
  }
}
```

---

## 📧 Email MFA Mutations

### initiateEmailMfaSetup

Initiates Email MFA setup by sending verification code.

**Authentication**: Required

**Returns:** `ok: Boolean`, `message: String`

```graphql
mutation SetupEmailMFA {
  initiateEmailMfaSetup {
    ok
    message
  }
}
```

### verifyEmailMfaSetup

Verifies and enables Email MFA.

**Authentication**: Required

**Arguments:**
- `otpCode: String!` - 6-digit code from email

**Returns:** `ok: Boolean`

```graphql
mutation VerifyEmailMFASetup {
  verifyEmailMfaSetup(otpCode: "123456") {
    ok
  }
}
```

### disableEmailMfa

Disables Email MFA for the user.

**Authentication**: Required

**Arguments:**
- `password: String!` - Current password for verification

**Returns:** `ok: Boolean`

```graphql
mutation DisableEmailMFA {
  disableEmailMfa(password: "current_password") {
    ok
  }
}
```

---

## 📱 SMS MFA Mutations

### initiateSmsMfaSetup

Initiates SMS MFA setup by sending verification code.

**Authentication**: Required
**Requirement**: Verified phone number

**Returns:** `ok: Boolean`, `message: String`

```graphql
mutation SetupSMSMFA {
  initiateSmsMfaSetup {
    ok
    message
  }
}
```

### verifySmsMfaSetup

Verifies and enables SMS MFA.

**Authentication**: Required

**Arguments:**
- `otpCode: String!` - 6-digit code from SMS

**Returns:** `ok: Boolean`

```graphql
mutation VerifySMSMFASetup {
  verifySmsMfaSetup(otpCode: "123456") {
    ok
  }
}
```

### disableSmsMfa

Disables SMS MFA for the user.

**Authentication**: Required

**Arguments:**
- `password: String!` - Current password for verification

**Returns:** `ok: Boolean`

```graphql
mutation DisableSMSMFA {
  disableSmsMfa(password: "current_password") {
    ok
  }
}
```

---

## 🔄 Common Usage Patterns

### Complete Registration Flow

```graphql
# 1. Register user
mutation {
  register(email: "user@example.com", password: "password", passwordConfirm: "password") {
    authPayload { user { id } accessToken }
    errors
  }
}

# 2. Verify email (user receives OTP via email)
mutation {
  verifyEmail(otpCode: "123456") {
    authPayload { user { emailVerified } }
    errors
  }
}
```

### Complete MFA Setup Flow

```graphql
# 1. Setup TOTP
mutation {
  initiateTotpSetup {
    qrCodeImage  # Show QR code to user
    mfaSecret    # Or manual entry
    errors
  }
}

# 2. Verify TOTP setup
mutation {
  verifyTotpSetup(otpCode: "123456") {
    ok
    user { totpMfaEnabled }
    errors
  }
}

# 3. Add phone number for SMS MFA
mutation {
  addPhoneNumber(phoneNumber: "+1234567890") {
    ok
    errors
  }
}

# 4. Verify phone number
mutation {
  verifyPhoneNumber(otpCode: "123456") {
    ok
    user { phoneNumberVerified }
    errors
  }
}

# 5. Setup SMS MFA
mutation {
  initiateSmsMfaSetup { ok }
}

mutation {
  verifySmsMfaSetup(otpCode: "123456") { ok }
}
```

### Complete Phone Number Management Flow

```graphql
# 1. Add initial phone number
mutation {
  addPhoneNumber(phoneNumber: "+1234567890") {
    ok
    message
    errors
  }
}

# 2. Verify phone number
mutation {
  verifyPhoneNumber(otpCode: "123456") {
    ok
    user {
      phoneNumber
      phoneNumberVerified
    }
    errors
  }
}

# 3. Update to new phone number (optional)
mutation {
  updatePhoneNumber(phoneNumber: "+1987654321") {
    ok
    message  # "Phone number updated. A verification code has been sent..."
    errors
  }
}

# 4. Verify new phone number
mutation {
  verifyPhoneNumber(otpCode: "654321") {
    ok
    user { phoneNumberVerified }
    errors
  }
}

# 5. Resend verification if needed
mutation {
  resendPhoneVerification {
    ok
    message
    errors
  }
}

# 6. Remove phone number (requires password)
mutation {
  removePhoneNumber(password: "current_password") {
    ok
    user {
      phoneNumber        # Will be null
      phoneNumberVerified # Will be false
      smsMfaEnabled      # Will be false if was enabled
    }
    errors
  }
}
```

### Phone Number Management Features

The phone number management system provides complete lifecycle management:

#### **Security Features:**
- **Format Validation**: Only E.164 format accepted (e.g., +1234567890)
- **Uniqueness**: Prevents multiple users from having the same verified number
- **Password Protection**: Phone removal requires password confirmation
- **Automatic MFA Management**: SMS MFA disabled when phone number changes

#### **User Experience:**
- **Seamless Updates**: Change phone numbers without losing account access
- **Verification Required**: All new/updated numbers must be verified
- **Resend Capability**: Can resend verification codes if not received
- **Clear Messaging**: Informative success and error messages

#### **Integration with MFA:**
- **SMS MFA Dependency**: SMS MFA requires verified phone number
- **Automatic Disabling**: SMS MFA disabled when phone number removed/changed
- **Re-enable After Verification**: SMS MFA can be re-enabled after new number verified

### MFA Login Flow

```graphql
# 1. Initial login
mutation {
  login(email: "user@example.com", password: "password") {
    authPayload {
      mfaRequired
      mfaToken
      enabledMfaMethods  # ["TOTP", "SMS", "EMAIL"]
    }
    errors
  }
}

# 2. Complete MFA (if required)
mutation {
  verifyMfa(mfaToken: "mfa_token", otpCode: "123456") {
    authPayload {
      accessToken
      refreshToken
    }
    errors
  }
}
```

---

## 🚨 Error Handling

### Common Error Types

- **Validation Errors**: Invalid input format or missing required fields
- **Authentication Errors**: Invalid credentials or expired tokens
- **Authorization Errors**: Insufficient permissions
- **Rate Limiting**: Too many requests
- **External Service Errors**: Social auth provider issues

### Error Response Format

```json
{
  "data": {
    "login": {
      "authPayload": null,
      "errors": [
        "Invalid credentials.",
        "Account is suspended. Reason: Policy violation."
      ]
    }
  }
}
```

### Best Practices

1. **Always check the `errors` field** in mutation responses
2. **Handle MFA flow** by checking `mfaRequired` in auth responses
3. **Refresh tokens proactively** before they expire
4. **Store tokens securely** (httpOnly cookies recommended)
5. **Implement proper error handling** for network and GraphQL errors

---

## 📚 Additional Resources

- **GraphiQL Interface**: Available at `/graphql` in development
- **Schema Introspection**: Use GraphQL introspection for latest schema
- **Rate Limiting**: Implement client-side rate limiting for better UX
- **Security**: Always use HTTPS in production

---

## 📋 API Summary

### Complete Mutation List

#### Authentication & Registration
- `register` - User registration (firstName/lastName required)
- `login` - User login with optional MFA
- `verifyMfa` - Complete MFA verification
- `refreshToken` - Get new access token
- `logout` - Invalidate refresh token
- `getScopedAccessToken` - Get organization-scoped token

#### Social Authentication
- `loginWithGoogle` - Google OAuth2 login
- `loginWithMicrosoft` - Microsoft OAuth2 login
- `loginWithLinkedin` - LinkedIn OAuth2 login

#### Profile & Password Management
- `updateProfile` - Update user profile (firstName/lastName)
- `changePassword` - Change password
- `initiatePasswordReset` - Start password reset
- `resetPasswordWithOtp` - Complete password reset

#### Email Verification
- `verifyEmail` - Verify email with OTP
- `resendVerificationEmail` - Resend verification email

#### Phone Number Management
- `addPhoneNumber` - Add phone number
- `verifyPhoneNumber` - Verify phone number
- `updatePhoneNumber` - Update phone number
- `removePhoneNumber` - Remove phone number
- `resendPhoneVerification` - Resend phone OTP

#### TOTP MFA
- `initiateTotpSetup` - Start TOTP setup
- `verifyTotpSetup` - Complete TOTP setup
- `disableTotp` - Disable TOTP

#### Email MFA
- `initiateEmailMfaSetup` - Start Email MFA
- `verifyEmailMfaSetup` - Complete Email MFA
- `disableEmailMfa` - Disable Email MFA

#### SMS MFA
- `initiateSmsMfaSetup` - Start SMS MFA
- `verifySmsMfaSetup` - Complete SMS MFA
- `disableSmsMfa` - Disable SMS MFA

### Key Requirements
- **Names Required**: firstName and lastName are mandatory for registration
- **Phone Format**: E.164 format required (+1234567890)
- **Email Verification**: Consistent across all authentication methods
- **MFA Dependencies**: SMS MFA requires verified phone number
- **Security**: Password required for phone number removal

---

*This documentation reflects the current implementation as of the latest update. For the most up-to-date schema, use GraphQL introspection or the GraphiQL interface.*
