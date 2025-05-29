# AfyaFlow Auth Service API Documentation (GraphQL)

This document outlines the GraphQL API for the AfyaFlow Auth Service. It provides examples of common queries and mutations that clients can use to interact with user authentication, management, and related functionalities.

---

## 🚀 Introduction

The AfyaFlow Auth Service is responsible for:
*   User registration and login (email/password).
*   Social authentication via Google OAuth 2.0.
*   JSON Web Token (JWT) management for session control (access and refresh tokens).
*   Multi-Factor Authentication (MFA) setup and verification.
*   User profile management (name, password changes).

The primary interface for these operations is a GraphQL API.

---

## 🔑 Authentication Mechanisms

### 1. JWT (JSON Web Token) Authentication

*   **Obtaining Tokens:** JWTs (access and refresh tokens) are provided upon successful user registration (`register` mutation) or login (`login`, `loginWithGoogle` mutations) within the `AuthPayloadType`.
*   **Using Access Tokens:** For authenticated requests to the GraphQL API, the client must include the access token in the `Authorization` header with the `Bearer` scheme:
    ```
    Authorization: Bearer <your_access_token>
    ```
*   **Access Token Lifetime:** Access tokens are short-lived (default: 30 minutes).
*   **Refresh Tokens:** When an access token expires, a new one can be obtained using the `refreshToken` mutation, providing the longer-lived refresh token. Refresh tokens are stored by the system and associated with the user.
*   **Logout:** The `logout` mutation invalidates the provided refresh token.

### 2. Google OAuth 2.0

*   Users can register or log in using their Google accounts.
*   **Flow:**
    1.  The client application obtains an `id_token` from Google upon successful user authentication on the frontend.
    2.  This `id_token` is sent to the `loginWithGoogle` GraphQL mutation.
    3.  The backend verifies the `id_token` with Google, then either creates a new AfyaFlow user (if one doesn't exist for that Google account's email) or logs in the existing user.
    4.  JWTs (access and refresh tokens) are returned, similar to email/password login.
*   **Django-Allauth:** The underlying Google OAuth flow (communication with Google, user creation/linking) is facilitated by `django-allauth`. Standard `django-allauth` views are also available under the `/accounts/` path (e.g., `/accounts/google/login/` to initiate the flow from a web context if needed).

---

## 🌐 GraphQL API Endpoint

All GraphQL requests should be sent to:

*   **`POST /graphql`**

The GraphiQL interface (an in-browser IDE for exploring GraphQL) is available at this endpoint when `DEBUG` is `True`.

---

## 🧩 Key GraphQL Types

#### `UserType`
Represents a user within the Afyaflow system.

*   **Fields:**
    *   `id: UUID!` (Read-only)
    *   `email: String!` (Read-only)
    *   `firstName: String`
    *   `lastName: String`
    *   `isActive: Boolean!` (Read-only)
    *   `isStaff: Boolean!` (Read-only)
    *   `isSuperuser: Boolean!` (Read-only)
    *   `isSuspended: Boolean!` (Read-only)
    *   `mfaEnabled: Boolean!` (Read-only)
    *   `dateJoined: DateTime!` (Read-only)
    *   `lastLogin: DateTime` (Read-only)

#### `AuthPayloadType`
Payload returned after successful authentication or token refresh.

*   **Fields:**
    *   `user: UserType!`
    *   `accessToken: String!`
    *   `refreshToken: String!`
    *   `organizationContext: OrganizationContextType` (Optional: context if an `organizationId` was provided and validated during login)
    *   `errors: [String]` (List of error messages if any part of the operation failed, e.g., login successful but org context fetch failed)

#### `OrganizationContextType`
Basic context of an organization (fetched from an external service if `organizationId` is used during login).

*   **Fields:**
    *   `id: UUID!`
    *   `name: String!`
    *   `slug: String!`
    *   `userRoleInOrg: String`

#### Error Handling
Mutations generally return an `errors: [String]` field. If the list is populated, it indicates issues with the request (e.g., validation errors, invalid credentials). If the primary operation was successful but a secondary one failed (like fetching organization context), the main payload might still be returned alongside errors.

---

## ❓ GraphQL Queries

### `me`
Returns the profile of the currently authenticated user. Requires a valid JWT access token.
**Example:**
```
{
  "Authentication": "Bearer valid-access-token"
}
```

*   **Returns:** `UserType`
*   **Description:** Fetches details for the user identified by the JWT in the `Authorization` header. Returns `null` or an error if not authenticated.

*   **Example:**
    ```graphql
    query GetCurrentUser {
      me {
        id
        email
        firstName
        lastName
        mfaEnabled
      }
    }
    ```

---

## 🔄 GraphQL Mutations

### 1. `register`
Registers a new user in the system.

*   **Arguments:**
    *   `email: String!`
    *   `password: String!` (Min length 8, other validations may apply)
    *   `passwordConfirm: String!`
    *   `firstName: String` (Optional)
    *   `lastName: String` (Optional)
*   **Returns:** `authPayload: AuthPayloadType`, `errors: [String]`
*   **Description:** Creates a new user account and returns JWTs upon success.

*   **Example:**
    ```graphql
    mutation RegisterNewUser {
      register(
        email: "newuser@example.com",
        password: "StrongPassword123!",
        passwordConfirm: "StrongPassword123!",
        firstName: "John",
        lastName: "Doe"
      ) {
        authPayload {
          user {
            id
            email
            firstName
          }
          accessToken
          refreshToken
        }
        errors
      }
    }
    ```

### 2. `login`
Logs in an existing user.

*   **Arguments:**
    *   `email: String!`
    *   `password: String!`
    *   `organizationId: UUID` (Optional: ID of an organization to associate with the session context)
    *   `mfaCode: String` (Optional: Required if MFA is enabled and setup for the user)
*   **Returns:** `authPayload: AuthPayloadType`, `errors: [String]`
*   **Description:** Authenticates a user and returns JWTs. If `organizationId` is provided, attempts to fetch context from an external organization service.

*   **Example (Basic Login):**
    ```graphql
    mutation LoginUser {
      login(email: "newuser@example.com", password: "StrongPassword123!") {
        authPayload {
          user { id email }
          accessToken
          refreshToken
        }
        errors
      }
    }
    ```
*   **Example (Login with MFA and Organization ID):**
    ```graphql
    mutation LoginUserWithMFAAndOrg {
      login(
        email: "user@example.com",
        password: "Password123!",
        mfaCode: "123456",
        organizationId: "org-uuid-here"
      ) {
        authPayload {
          user { id email }
          accessToken
          refreshToken
          organizationContext {
            id
            name
            userRoleInOrg
          }
        }
        errors
      }
    }
    ```

### 3. `refreshToken`
Obtains a new access token using a valid refresh token.

*   **Arguments:**
    *   `refreshToken: String!`
*   **Returns:** returns `accessToken: String`, `user: UserType`, `errors: [String]` 
*   **Description:** Issues a new access token if the refresh token is valid and not revoked.

*   **Example:**
     ```graphql
    mutation RefreshUserToken {
      refreshToken(refreshToken: "your_long_lived_refresh_token_here") {
        accessToken # New access token
        user { id email } # Typically includes user for context
        errors
      }
    }
    ```
    

### 4. `logout`
Logs out a user by revoking their refresh token.

*   **Arguments:**
    *   `refreshToken: String!`
*   **Returns:** `ok: Boolean`, `message: String`, `errors: [String]`
*   **Description:** Invalidates the provided refresh token, effectively logging the user out from sessions relying on it.

*   **Example:**
    ```graphql
    mutation LogoutUser {
      logout(refreshToken: "user_refresh_token_to_revoke") {
        ok
        message
        errors
      }
    }
    ```

### 5. `updateProfile`
Updates the authenticated user's profile information. Requires authentication.

*   **Arguments:**
    *   `firstName: String` (Optional)
    *   `lastName: String` (Optional)
*   **Returns:** `user: UserType`, `errors: [String]`
*   **Description:** Modifies the first name and/or last name of the logged-in user.

*   **Example:**
    ```graphql
    mutation UpdateUserProfile {
      updateProfile(firstName: "Jane", lastName: "Doer") {
        user {
          id
          firstName
          lastName
          email
        }
        errors
      }
    }
    ```

### 6. `changePassword`
Allows an authenticated user to change their password. Requires authentication.

*   **Arguments:**
    *   `oldPassword: String!`
    *   `newPassword: String!`
    *   `newPasswordConfirm: String!`
*   **Returns:** `ok: Boolean`, `message: String`, `errors: [String]`
*   **Description:** Updates the user's password after verifying the old one.

*   **Example:**
    ```graphql
    mutation ChangeUserPassword {
      changePassword(
        oldPassword: "CurrentPassword123!",
        newPassword: "NewStrongPassword456!",
        newPasswordConfirm: "NewStrongPassword456!"
      ) {
        ok
        message
        errors
      }
    }
    ```

### 7. `initiateMfaSetup`
Initiates the MFA setup process for the authenticated user. Requires authentication.

*   **Arguments:** (None)
*   **Returns:** `otpProvisioningUri: String`, `mfaSecret: String`, `ok: Boolean`, `errors: [String]`
*   **Description:** Generates an MFA secret and a provisioning URI (for QR codes). The user's MFA is not yet enabled at this stage.

*   **Example:**
    ```graphql
    mutation StartMFASetup {
      initiateMfaSetup {
        otpProvisioningUri # e.g., "otpauth://totp/AfyaFlow:user@example.com?secret=YOURSECRET&issuer=AfyaFlow"
        mfaSecret          # The secret key
        ok
        errors
      }
    }
    ```

### 8. `verifyMfaSetup`
Verifies the OTP code and enables MFA for the authenticated user. Requires authentication.

*   **Arguments:**
    *   `otpCode: String!` (The 6-digit code from the authenticator app)
*   **Returns:** `ok: Boolean`, `user: UserType`, `errors: [String]`
*   **Description:** Confirms the MFA setup by verifying an OTP. If successful, MFA is enabled for the user.

*   **Example:**
    ```graphql
    mutation CompleteMFASetup {
      verifyMfaSetup(otpCode: "654321") {
        ok
        user {
          id
          email
          mfaEnabled
        }
        
      }
    }
    ```

### 9. `disableMfa`
Disables MFA for the authenticated user after verification. Requires authentication.

*   **Arguments:**
    *   `otpCode: String!` (A current OTP code to verify identity)
*   **Returns:** `ok: Boolean`, `user: UserType`, `errors: [String]`
*   **Description:** Turns off MFA for the user's account. Requires a current OTP to confirm the action.

*   **Example:**
    ```graphql
    mutation TurnOffMFA {
      disableMfa(otpCode: "123789") {
        ok
        user {
          id
          email
          mfaEnabled
        }
        errors
      }
    }
    ```

### 10. `loginWithGoogle`
Logs in or registers a user using a Google ID Token.

*   **Arguments:**
    *   `idToken: String!` (The ID token obtained from Google on the client-side)
    *   `organizationId: UUID` (Optional: ID of an organization to associate with the session context)
*   **Returns:** `authPayload: AuthPayloadType`, `errors: [String]`
*   **Description:** Authenticates a user via Google. If the user doesn't exist, a new account is created. Returns JWTs.

*   **Example:**
    ```graphql
    mutation SignInWithGoogle {
      loginWithGoogle(
        idToken: "google_id_token_string_from_client",
        organizationId: "optional-org-uuid-here"
      ) {
        authPayload {
          user {
            id
            email
            firstName
            lastName
          }
          accessToken
          refreshToken
          organizationContext { # if organizationId was provided and valid
            id
            name
          }
        }
        errors
      }
    }
    ```

---

## 🌐 Standard Account Management (via `django-allauth`)

While the primary API is GraphQL, `django-allauth` also provides traditional web-based views for certain account management tasks, accessible under the `/accounts/` path prefix. These are typically used if you have server-rendered templates for these flows.

*   **Google Login Initiation (Web Flow):** `/accounts/google/login/`
*   **Password Reset:** (e.g., `/accounts/password/reset/`)
*   **Email Management:** (e.g., `/accounts/email/` for adding/verifying emails, if enabled)

These endpoints are part of `django-allauth` and may not be directly invoked by a client that exclusively uses the GraphQL API for authentication, but they exist as part of the integrated authentication system.

--- 