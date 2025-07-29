# AfyaFlow Auth Service API Documentation (GraphQL)

This document provides comprehensive documentation for the AfyaFlow Auth Service GraphQL API. It includes all available queries, mutations, types, and examples for user authentication, multi-factor authentication, profile management, social authentication, and the new gateway-compliant features.

---

## 🚀 Introduction

The AfyaFlow Auth Service provides a complete authentication and user management solution with the following features:

### Core Features
- **Multi-User Type System** - Support for providers, patients, and operations users
- **User Registration & Login** - Email/password authentication with email verification
- **Patient Passwordless Authentication** - Phone/email + OTP authentication for patients
- **Social Authentication** - Google, Microsoft, and LinkedIn OAuth2 integration
- **Multi-Factor Authentication (MFA)** - TOTP (Authenticator apps), SMS, and Email MFA
- **JWT System** - User-type-specific secrets and enhanced security
- **Dual-Role Support** - Providers can access patient services seamlessly
- **Service-to-Service Authentication** - X-Service-Auth-ID header support
- **Profile Management** - User profile updates, password changes, and account management
- **Phone Number Management** - Add and verify phone numbers for SMS MFA
- **Email Management** - Add real emails for phone-only users
- **Password Reset** - Secure password reset with OTP verification

### GraphQL Endpoint
- **URL**: `/graphql`
- **Development**: GraphiQL interface available at `/graphql` when `DEBUG=True`

---

## 🔐 Authentication & Authorization

### User Types

The AfyaFlow system supports three distinct user types, each with specific authentication requirements:

#### Provider Users (Healthcare Professionals)
- **User Type**: `provider`
- **Authentication**: Email/password + optional MFA
- **JWT Secret**: `PROVIDER_AUTH_TOKEN_SECRET`
- **Organization Context**: Required for most operations (OCT)
- **Dual-Role**: Can access patient services when enabled

#### Patient Users
- **User Type**: `patient`
- **Authentication**: Email/password OR phone/email + OTP (passwordless)
- **JWT Secret**: `PATIENT_AUTH_TOKEN_SECRET`
- **Organization Context**: Not used
- **Features**: Passwordless authentication, smart email placeholders

#### Operations Users (Admin/Support)
- **User Type**: `operations`
- **Authentication**: Email/password + optional MFA
- **JWT Secret**: `OPERATIONS_AUTH_TOKEN_SECRET`
- **Organization Context**: Not used
- **Access**: System-wide or cross-tenant

### JWT Token System

The service uses a gateway-compliant JWT system with user-type-specific secrets:

#### Access Tokens
- **Purpose**: Authenticate API requests
- **Lifetime**: 30 minutes (configurable)
- **Usage**: Include in `Authorization` header as `Bearer <token>`
- **Contains**: User ID, user_type, permissions, current_context (for dual-role)
- **Secrets**: Different secret per user type for enhanced security

#### Refresh Tokens
- **Purpose**: Obtain new access tokens without re-authentication
- **Lifetime**: 7 days (configurable)
- **Storage**: Stored securely in database, can be revoked
- **Usage**: Use with `refreshToken` mutation

#### Organization Context Tokens (OCT)
- **Purpose**: Access organization-specific resources (providers only)
- **Lifetime**: Same as access tokens
- **Usage**: Obtained via `getScopedAccessToken` mutation
- **Contains**: User permissions within specific organization

#### Service Authentication
- **Purpose**: Service-to-service communication
- **Usage**: Include `X-Service-Auth-ID` header
- **Format**: Service account ID (e.g., `billing-svc-123abc`)
- **Validation**: Against gateway's service account registry

### Authentication Flows

#### Provider Authentication Flow
```
1. Provider registers/logs in → Receives access + refresh tokens (PROVIDER_AUTH_TOKEN_SECRET)
2. Use access token for API requests
3. When access token expires → Use refresh token to get new access token
4. For organization operations → Get OCT with getScopedAccessToken
5. For patient services → Enable patient profile, get patient-context tokens
```


#### Patient Authentication Flow (Passwordless)
```
1. Patient initiates auth with phone/email → Receives OTP
2. Patient verifies OTP → Receives access + refresh tokens (PATIENT_AUTH_TOKEN_SECRET)
3. Use access token for API requests
4. Optional: Add real email to replace placeholder
```

#### Operations Authentication Flow
```
1. Operations user logs in → Receives access + refresh tokens (OPERATIONS_AUTH_TOKEN_SECRET)
2. Use access token for system-wide operations
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

Represents a user in the AfyaFlow system with enhanced user type support.

```graphql
type User {
  id: UUID!
  email: String!
  firstName: String!
  lastName: String!
  userType: String!  # "provider", "patient", or "operations"
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

  # Dual-Role Support (Providers)
  patientProfileEnabled: Boolean!
  patientServicesFirstUsed: DateTime

  # Email Management
  hasRealEmail: Boolean!  # True if not a placeholder email
  canReceiveEmail: Boolean!  # True if can send real emails
  needsRealEmail: Boolean!  # True if should be prompted to add real email
}
```

### AuthPayloadType

Returned by authentication mutations (login, register, social auth, patient auth).

```graphql
type AuthPayload {
  user: User
  accessToken: String  # Signed with user-type-specific secret
  refreshToken: String
  mfaRequired: Boolean!
  mfaToken: String
  enabledMfaMethods: [String]
  organizationMemberships: [OrganizationMembership]

  # Additional context for dual-role users
  currentContext: String  # "patient" when provider uses patient services
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

### Traditional Authentication (All User Types)

### register

Registers a new user and sends email verification OTP. Creates provider or operations users.

**Arguments:**
- `email: String!` - User's email address
- `password: String!` - Password (min 8 characters)
- `passwordConfirm: String!` - Password confirmation
- `firstName: String!` - User's first name (required)
- `lastName: String!` - User's last name (required)
- `userType: String` - "provider" or "operations" (defaults to "provider")

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation RegisterUser {
  register(
    email: "user@example.com"
    password: "SecurePassword123!"
    passwordConfirm: "SecurePassword123!"
    firstName: "John"    # Required
    lastName: "Doe"      # Required
    userType: "provider" # Optional, defaults to "provider"
  ) {
    authPayload {
      user {
        id
        email
        firstName
        lastName
        userType
        emailVerified
      }
      accessToken  # Signed with PROVIDER_AUTH_TOKEN_SECRET
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

## 📱 Patient Passwordless Authentication

### initiatePatientAuth

Initiates passwordless authentication for patients using phone number or email.

**Arguments:**
- `identifier: String!` - Phone number (E.164 format) or email address
- `firstName: String` - First name (required for new users)
- `lastName: String` - Last name (required for new users)

**Returns:** `success: Boolean`, `message: String`, `isNewUser: Boolean`

```graphql
mutation InitiatePatientAuth {
  initiatePatientAuth(
    identifier: "+254799275131"  # or "patient@example.com"
    firstName: "John"            # Required for new users
    lastName: "Paul"          # Required for new users
  ) {
    success
    message
    isNewUser  # True if this creates a new account
  }
}
```

### completePatientAuth

Completes passwordless authentication by verifying the OTP code.

**Arguments:**
- `identifier: String!` - Same identifier used in initiate step
- `otpCode: String!` - 6-digit OTP code received via SMS/email

**Returns:** `AuthPayload`, `errors: [String]`

```graphql
mutation CompletePatientAuth {
  completePatientAuth(
    identifier: "+254799275131"
    otpCode: "123456"
  ) {
    authPayload {
      user {
        id
        email          # May be placeholder for phone-only users
        userType       # Always "patient"
        hasRealEmail   # False for phone-only users
        needsRealEmail # True if should add real email
      }
      accessToken      # Signed with PATIENT_AUTH_TOKEN_SECRET
      refreshToken
    }
    errors
  }
}
```

### Patient Email Management

For phone-only patients who want to add a real email address:

#### addEmail

Adds a real email address for phone-only users.

**Authentication**: Required (patient with placeholder email)

**Arguments:**
- `email: String!` - Real email address to add

**Returns:** `success: Boolean`, `message: String`, `verificationRequired: Boolean`

```graphql
mutation AddRealEmail {
  addEmail(email: "patient@gmail.com") {
    success
    message
    verificationRequired  # Always true
  }
}
```

#### verifyAddEmail

Verifies and completes email addition.

**Authentication**: Required

**Arguments:**
- `otpCode: String!` - OTP code from email

**Returns:** `success: Boolean`, `message: String`, `user: User`

```graphql
mutation VerifyAddEmail {
  verifyAddEmail(otpCode: "123456") {
    success
    message
    user {
      email          # Now the real email
      hasRealEmail   # Now true
      canReceiveEmail # Now true
    }
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

### Provider Registration Flow

```graphql
# 1. Register provider
mutation {
  register(
    email: "dr.smith@hospital.com"
    password: "SecurePass123!"
    passwordConfirm: "SecurePass123!"
    firstName: "Dr. John"
    lastName: "Smith"
    userType: "provider"
  ) {
    authPayload {
      user { id userType }
      accessToken  # PROVIDER_AUTH_TOKEN_SECRET
    }
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

### Patient Passwordless Registration Flow

```graphql
# 1. Initiate patient auth with phone
mutation {
  initiatePatientAuth(
    identifier: "+25479922231"
    firstName: "John"
    lastName: "Patient"
  ) {
    success
    message
    isNewUser  # true for new registration
  }
}

# 2. Complete auth with OTP (user receives SMS)
mutation {
  completePatientAuth(
    identifier: "+254799275131"
    otpCode: "123456"
  ) {
    authPayload {
      user {
        id
        userType        # "patient"
        email          # "phone.25479927221@afyaflow.app"
        hasRealEmail   # false
        needsRealEmail # true
      }
      accessToken      # PATIENT_AUTH_TOKEN_SECRET
    }
    errors
  }
}

# 3. Optional: Add real email
mutation {
  addEmail(email: "john@gmail.com") {
    success
    verificationRequired
  }
}

# 4. Verify real email
mutation {
  verifyAddEmail(otpCode: "654321") {
    success
    user {
      email          # "john@gmail.com"
      hasRealEmail   # true
      canReceiveEmail # true
    }
  }
}
```

### Provider Using Patient Services Flow

```graphql
# 1. Provider logs in normally
mutation {
  login(email: "dr.smith@hospital.com", password: "password") {
    authPayload {
      user { userType patientProfileEnabled }
      accessToken
    }
  }
}

# 2. Provider uses patient auth to enable patient services
mutation {
  initiatePatientAuth(identifier: "dr.smith@hospital.com") {
    success
    message
  }
}

# 3. Complete patient auth (enables dual-role)
mutation {
  completePatientAuth(
    identifier: "dr.smith@hospital.com"
    otpCode: "123456"
  ) {
    authPayload {
      user {
        userType              # "provider" (actual type)
        patientProfileEnabled # true (now enabled)
      }
      accessToken             # Contains current_context: "patient"
      currentContext          # "patient"
    }
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
- `register` - User registration (firstName/lastName required, userType optional)
- `login` - User login with optional MFA
- `verifyMfa` - Complete MFA verification
- `refreshToken` - Get new access token
- `logout` - Invalidate refresh token
- `getScopedAccessToken` - Get organization-scoped token

#### Patient Passwordless Authentication
- `initiatePatientAuth` - Start passwordless auth for patients
- `completePatientAuth` - Complete passwordless auth with OTP

#### Patient Email Management
- `addEmail` - Add real email for phone-only patients
- `verifyAddEmail` - Verify and complete email addition

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

### Key Requirements & Features

#### User Type System
- **Provider Users**: Email/password auth, organization context, dual-role support
- **Patient Users**: passwordless auth, no organization context
- **Operations Users**: Email/password auth, system-wide access

#### Gateway Compliance
- **User-Type-Specific Secrets**: Different JWT secrets per user type
- **Service Authentication**: X-Service-Auth-ID header support
- **Context Preservation**: current_context field for dual-role users

#### Security & Validation
- **Names Required**: firstName and lastName are mandatory for registration
- **Phone Format**: E.164 format required (+1234567890)
- **Email Verification**: Consistent across all authentication methods
- **MFA Dependencies**: SMS MFA requires verified phone number
- **Password Protection**: Password required for sensitive operations

#### Smart Email Management
- **Placeholder Emails**: Phone-only users get professional placeholders
- **Email Upgrade Path**: Phone-only users can add real emails
- **Email Detection**: System knows real vs placeholder emails

---

## 🚀 New Features Summary

### Gateway-Compliant JWT System
- **User-type-specific secrets** for enhanced security
- **Multi-secret validation** for backward compatibility
- **Service authentication** support via X-Service-Auth-ID header

### Patient Passwordless Authentication
- **Phone/email + OTP** authentication for patients
- **Smart email placeholders** for phone-only users
- **Real email upgrade path** with verification

### Dual-Role Support
- **Providers can access patient services** seamlessly
- **Context-aware tokens** with current_context field
- **Automatic patient profile enablement**

### Enhanced User Management
- **Three distinct user types** (provider, patient, operations)
- **User type validation** and appropriate token signing
- **Comprehensive email management** for all user types

---

*This documentation reflects the current implementation with all recent enhancements including gateway compliance, patient passwordless authentication, dual-role support, and enhanced JWT security. For the most up-to-date schema, use GraphQL introspection or the GraphiQL interface.*
