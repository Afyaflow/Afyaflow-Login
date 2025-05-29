import graphene
from graphene_django import DjangoObjectType
from .models import User, RefreshToken
from .authentication import create_token
from .serializers import UserRegistrationSerializer, UserProfileSerializer, ChangePasswordSerializer, MFASetupSerializer
from django.contrib.auth import authenticate, login as django_login # Renamed to avoid conflict
from django.utils import timezone # For updating last_login
import requests # For making HTTP requests to other services
from django.conf import settings # To get ORGANIZATION_SERVICE_URL
import pyotp # For MFA
import logging # Re-add logging

# Allauth imports
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.models import SocialApp, SocialLogin, SocialToken, SocialAccount
from allauth.socialaccount.helpers import complete_social_login, render_authentication_error
from allauth.exceptions import ImmediateHttpResponse
from django.http import HttpRequest # For creating a request object for allauth

class UserType(DjangoObjectType):
    """GraphQL type for the User model, representing a healthcare professional or system user."""
    class Meta:
        model = User
        fields = (
            "id", 
            "email", 
            "first_name", 
            "last_name", 
            "is_active", 
            "is_staff", 
            "is_superuser", 
            "is_suspended", 
            "mfa_enabled", 
            "date_joined", 
            "last_login"
        )
        description = "Represents a user within the Afyaflow system."
        # You can also use exclude = ("password", "other_sensitive_fields")

class OrganizationContextType(graphene.ObjectType):
    id = graphene.UUID(description="The unique identifier of the organization.")
    name = graphene.String(description="The name of the organization.")
    slug = graphene.String(description="The URL-friendly slug of the organization.")
    user_role_in_org = graphene.String(description="User's role in this specific organization (e.g., ADMIN, MEMBER).")
    
    class Meta:
        description = "Basic context of the organization selected or relevant during login."

class AuthPayloadType(graphene.ObjectType):
    """Payload returned after successful authentication (login or register)."""
    user = graphene.Field(UserType, description="The authenticated user object.")
    access_token = graphene.String(name="accessToken", description="JWT access token for authenticated requests.")
    refresh_token = graphene.String(name="refreshToken", description="JWT refresh token to obtain new access tokens.")
    organization_context = graphene.Field(OrganizationContextType, name="organizationContext", required=False, description="Context of the organization if specified and validated during login.")
    errors = graphene.List(graphene.String, description="List of error messages if any operation within the mutation fails.") # Added to Login, Register

# We will add Queries and Mutations here later

class UserQuery(graphene.ObjectType):
    """GraphQL queries related to users."""
    me = graphene.Field(UserType, description="Returns the currently authenticated user's profile.")

    def resolve_me(self, info):
        user = info.context.user
        if user.is_anonymous:
            # In GraphQL, it's common to return null for unauthenticated users
            # or raise an exception that Graphene can handle as an error.
            # For now, let's return None, which will result in null in the GraphQL response.
            return None 
        return user

# We will combine this into a root schema later
# schema = graphene.Schema(query=UserQuery) # Example for testing this app's schema in isolation 

class RegisterMutation(graphene.Mutation):
    """Registers a new user in the system."""
    class Arguments:
        email = graphene.String(required=True, description="User's email address (must be unique).")
        password = graphene.String(required=True, description="User's desired password.")
        password_confirm = graphene.String(required=True, description="Confirmation of the password.")
        first_name = graphene.String(description="User's first name.")
        last_name = graphene.String(description="User's last name.")

    auth_payload = graphene.Field(AuthPayloadType, description="Contains user object and tokens upon successful registration.")
    errors = graphene.List(graphene.String, description="List of error messages if registration fails.")

    @classmethod
    def mutate(cls, root, info, email, password, password_confirm, first_name=None, last_name=None):
        serializer_data = {
            'email': email,
            'password': password,
            'password_confirm': password_confirm,
            'first_name': first_name,
            'last_name': last_name
        }
        serializer_data = {k: v for k, v in serializer_data.items() if v is not None}

        serializer = UserRegistrationSerializer(data=serializer_data)
        if serializer.is_valid():
            user = serializer.save()

            access_token_str, _ = create_token(user.id, token_type='access')
            refresh_token_str, refresh_expires_at = create_token(user.id, token_type='refresh')

            RefreshToken.objects.create(
                user=user,
                token=refresh_token_str,
                expires_at=refresh_expires_at
            )
            
            auth_payload_instance = AuthPayloadType(
                user=user,
                access_token=access_token_str,
                refresh_token=refresh_token_str
            )
            return RegisterMutation(auth_payload=auth_payload_instance, errors=None)
        else:
            error_messages = []
            for field, messages in serializer.errors.items():
                for message in messages:
                    error_messages.append(f"{field}: {message}")
            return RegisterMutation(auth_payload=None, errors=error_messages)

class LoginMutation(graphene.Mutation):
    """Logs in an existing user."""
    class Arguments:
        email = graphene.String(required=True, description="User's registered email address.")
        password = graphene.String(required=True, description="User's password.")
        organization_id = graphene.UUID(required=False, name="organizationId", description="Optional: ID of the organization to log into.")
        mfa_code = graphene.String(required=False, name="mfaCode", description="The 6-digit MFA OTP code, required if MFA is enabled for the user.")

    auth_payload = graphene.Field(AuthPayloadType, description="Contains user object and tokens upon successful login.")
    errors = graphene.List(graphene.String, description="List of error messages if login fails.")

    @classmethod
    def mutate(cls, root, info, email, password, organization_id=None, mfa_code=None):
        user = authenticate(email=email, password=password)
        if not user:
            return LoginMutation(auth_payload=None, errors=["Invalid credentials."])
        if user.is_suspended:
            reason = getattr(user, 'suspension_reason', 'No reason provided.')
            return LoginMutation(auth_payload=None, errors=[f"Account is suspended. Reason: {reason}"])

        # MFA Check
        if user.mfa_enabled and user.mfa_setup_complete:
            if not mfa_code:
                return LoginMutation(auth_payload=None, errors=["MFA code is required."])
            if not user.mfa_secret:
                 # This case should ideally not happen if mfa_enabled and mfa_setup_complete are true,
                 # but as a safeguard:
                return LoginMutation(auth_payload=None, errors=["MFA is enabled but a secret is not configured. Please contact support."])
            
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(mfa_code):
                # You might want to add rate limiting or account lockout logic here for repeated failures
                return LoginMutation(auth_payload=None, errors=["Invalid MFA code."])
        elif mfa_code: # User provided an MFA code but MFA is not active/complete
            # Decide on behavior: ignore it, or tell them MFA isn't active.
            # For now, let's inform them if they try to use it when not needed/set up.
            if not user.mfa_enabled or not user.mfa_setup_complete:
                 return LoginMutation(auth_payload=None, errors=["MFA is not enabled for this account."])

        # Create JWT tokens
        access_token_str, _ = create_token(user.id, token_type='access')
        refresh_token_str, refresh_expires_at = create_token(user.id, token_type='refresh')

        # Save the refresh token
        RefreshToken.objects.create(
            user=user,
            token=refresh_token_str,
            expires_at=refresh_expires_at
        )

        # Update last_login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        org_context_instance = None
        mutation_errors = []

        if organization_id:
            org_service_url = getattr(settings, 'ORGANIZATION_SERVICE_URL', None)
            if not org_service_url:
                mutation_errors.append("Organization service URL is not configured.")
            else:
                query = """
                    query GetMembershipDetails($userId: String!, $organizationId: String!) {
                        organizationMembership(where: { userId_organizationId: { userId: $userId, organizationId: $organizationId }}) {
                            isActive
                            role
                            organization {
                                id
                                name
                                slug
                            }
                        }
                    }
                """
                variables = {
                    "userId": str(user.id),
                    "organizationId": str(organization_id)
                }
                try:
                    response = requests.post(
                        org_service_url,
                        json={'query': query, 'variables': variables},
                        headers={'Content-Type': 'application/json'}
                    )
                    response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                    
                    data = response.json()
                    
                    if data.get("errors"):
                        for error in data.get("errors", []):
                            mutation_errors.append(f"Organization service error: {error.get('message', 'Unknown error')}")
                    elif data.get("data") and data["data"].get("organizationMembership"):
                        membership = data["data"]["organizationMembership"]
                        if membership.get("isActive"):
                            org_details = membership.get("organization")
                            if org_details:
                                org_context_instance = OrganizationContextType(
                                    id=org_details.get("id"),
                                    name=org_details.get("name"),
                                    slug=org_details.get("slug"),
                                    user_role_in_org=membership.get("role")
                                )
                            else:
                                mutation_errors.append("Organization details not found in membership.")
                        else:
                            mutation_errors.append("User membership in the specified organization is not active.")
                    else:
                        mutation_errors.append("User not found in the specified organization or membership is inactive.")
                        
                except requests.exceptions.RequestException as e:
                    mutation_errors.append(f"Could not connect to organization service: {str(e)}")
                except ValueError: # Includes JSONDecodeError
                    mutation_errors.append("Invalid response from organization service.")

        auth_payload_instance = AuthPayloadType(
            user=user,
            access_token=access_token_str,
            refresh_token=refresh_token_str,
            organization_context=org_context_instance
        )
        
        # If there were errors fetching org context, but login itself was successful,
        # we still return the auth_payload, but include the errors.
        if mutation_errors:
             return LoginMutation(auth_payload=auth_payload_instance, errors=mutation_errors)
        
        return LoginMutation(auth_payload=auth_payload_instance, errors=None)

class RefreshTokenMutation(graphene.Mutation):
    class Arguments:
        refresh_token = graphene.String(required=True)

    access_token = graphene.String() # Output field

    @classmethod
    def mutate(cls, root, info, refresh_token):
        try:
            token_obj = RefreshToken.objects.get(
                token=refresh_token,
                expires_at__gt=timezone.now(),
                is_revoked=False
            )
        except RefreshToken.DoesNotExist:
            raise Exception("Invalid or expired refresh token")

        # Create new access token
        new_access_token_str, _ = create_token(token_obj.user.id, token_type='access')

        return RefreshTokenMutation(access_token=new_access_token_str)

class LogoutMutation(graphene.Mutation):
    class Arguments:
        refresh_token = graphene.String(required=True)

    ok = graphene.Boolean() # Indicates success
    message = graphene.String()

    @classmethod
    def mutate(cls, root, info, refresh_token):
        try:
            token_obj = RefreshToken.objects.get(
                token=refresh_token,
                # expires_at__gt=timezone.now(), # Optional: Allow logout even if expired for cleanup
                is_revoked=False
            )
            token_obj.is_revoked = True
            token_obj.save()
            return LogoutMutation(ok=True, message="Successfully logged out.")
        except RefreshToken.DoesNotExist:
            # Depending on desired behavior, you could silently succeed or indicate token was not found/active
            # For now, let's indicate it wasn't an active token that was logged out.
            return LogoutMutation(ok=False, message="Invalid or already revoked refresh token.")

class UpdateProfileMutation(graphene.Mutation):
    class Arguments:
        first_name = graphene.String()
        last_name = graphene.String()
        # Add other fields a user can update here, e.g., preferences if any

    user = graphene.Field(UserType)
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, first_name=None, last_name=None):
        user = info.context.user
        if user.is_anonymous:
            return UpdateProfileMutation(user=None, errors=["User is not authenticated."])

        # Use UserProfileSerializer for validation and partial update
        # We pass the user instance to update it
        update_data = {}
        if first_name is not None: # Graphene doesn't distinguish between empty string and not provided
            update_data['first_name'] = first_name
        if last_name is not None:
            update_data['last_name'] = last_name
        
        if not update_data: # Nothing to update
             return UpdateProfileMutation(user=user, errors=["No update data provided."])

        # Note: UserProfileSerializer might not be ideal if it exposes fields 
        # the user shouldn't directly set (like email, is_active etc via this mutation).
        # A dedicated ProfileUpdateSerializer might be better for fine-grained control.
        # For now, assuming UserProfileSerializer handles partial updates safely.
        serializer = UserProfileSerializer(user, data=update_data, partial=True)
        if serializer.is_valid():
            updated_user = serializer.save()
            return UpdateProfileMutation(user=updated_user, errors=None)
        else:
            error_messages = []
            for field, messages in serializer.errors.items():
                for message in messages:
                    error_messages.append(f"{field}: {message}")
            return UpdateProfileMutation(user=None, errors=error_messages)

class ChangePasswordMutation(graphene.Mutation):
    class Arguments:
        old_password = graphene.String(required=True)
        new_password = graphene.String(required=True)
        new_password_confirm = graphene.String(required=True)

    ok = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, old_password, new_password, new_password_confirm):
        user = info.context.user
        if user.is_anonymous:
            return ChangePasswordMutation(ok=False, errors=["User is not authenticated."])

        if new_password != new_password_confirm:
            return ChangePasswordMutation(ok=False, errors=["New passwords do not match."])

        # Use ChangePasswordSerializer for validation (primarily for password strength if defined)
        # and checking old password
        # Note: We are not using serializer.save() directly here as we handle password setting and token revocation.
        serializer = ChangePasswordSerializer(data={'old_password': old_password, 'new_password': new_password}, context={'request': info.context})
        
        # Manual check for old_password as serializer might not expose it easily
        if not user.check_password(old_password):
            return ChangePasswordMutation(ok=False, errors=["Incorrect old password."])
        
        # Validate the new password (e.g., strength rules defined in serializer or Django settings)
        # The ChangePasswordSerializer in DRF typically doesn't validate old_password itself but expects it for context.
        # It validates the new_password based on Django's password validators.
        # We need to ensure it validates the new_password correctly.
        # A simpler way if serializer doesn't fit: user.set_password() and user.full_clean() for validation
        try:
            # This is a bit of a workaround to trigger new_password validation via the serializer
            # if the serializer is set up for it (e.g. using validate_new_password method)
            # A more direct way would be to call Django's validate_password directly.
            from django.contrib.auth.password_validation import validate_password
            validate_password(new_password, user=user)
        except Exception as e: # Catches Django's ValidationError
            error_messages = [str(err) for err in e.messages] if hasattr(e, 'messages') else [str(e)]
            return ChangePasswordMutation(ok=False, errors=error_messages)

        user.set_password(new_password)
        user.save()

        # Revoke all refresh tokens for the user upon password change
        RefreshToken.objects.filter(user=user).update(is_revoked=True)

        return ChangePasswordMutation(ok=True, message="Password updated successfully.")

class InitiateMFASetupMutation(graphene.Mutation):
    class Arguments:
        # No arguments needed, acts on the authenticated user
        pass

    otp_provisioning_uri = graphene.String(
        description="The OTP provisioning URI for QR code generation (e.g., otpauth://totp/...)"
    )
    mfa_secret = graphene.String(
        description="The MFA secret key. Store this securely if needed, though usually the URI is enough for QR."
    )
    ok = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info):
        user = info.context.user
        if user.is_anonymous:
            return InitiateMFASetupMutation(ok=False, errors=["User is not authenticated."])

        if user.mfa_enabled and user.mfa_setup_complete:
            return InitiateMFASetupMutation(ok=False, errors=["MFA is already set up and verified. Disable it first if you want to re-setup."])

        # Generate a new MFA secret
        # pyotp.random_base32() generates a 16-character base32 secret (compatible with Google Authenticator)
        # For a 32-character secret, you could call it twice or specify length if library supports, but 16 is standard.
        temp_secret = pyotp.random_base32()
        user.mfa_secret = temp_secret
        user.mfa_enabled = False  # Not fully enabled until verified
        user.mfa_setup_complete = False
        user.save(update_fields=['mfa_secret', 'mfa_enabled', 'mfa_setup_complete'])

        # Generate OTP provisioning URI
        # Format: otpauth://totp/ISSUER_NAME:USER_EMAIL?secret=SECRET_KEY&issuer=ISSUER_NAME
        issuer_name = "Afyaflow" # You can make this a setting
        otp_uri = pyotp.totp.TOTP(temp_secret).provisioning_uri(
            name=user.email, 
            issuer_name=issuer_name
        )

        return InitiateMFASetupMutation(
            ok=True, 
            otp_provisioning_uri=otp_uri, 
            mfa_secret=temp_secret # Return secret for potential manual entry by user
        )

class VerifyMFASetupMutation(graphene.Mutation):
    class Arguments:
        otp_code = graphene.String(required=True, description="The 6-digit OTP code from the authenticator app.")

    ok = graphene.Boolean()
    user = graphene.Field(UserType, description="The user with updated MFA status.")
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, otp_code):
        user = info.context.user
        if user.is_anonymous:
            return VerifyMFASetupMutation(ok=False, errors=["User is not authenticated."])

        if not user.mfa_secret:
            return VerifyMFASetupMutation(ok=False, errors=["MFA setup has not been initiated. Please initiate MFA setup first."])
        
        if user.mfa_enabled and user.mfa_setup_complete:
            return VerifyMFASetupMutation(ok=False, errors=["MFA is already verified and enabled."])

        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(otp_code):
            user.mfa_enabled = True
            user.mfa_setup_complete = True
            user.save(update_fields=['mfa_enabled', 'mfa_setup_complete'])
            return VerifyMFASetupMutation(ok=True, user=user)
        else:
            return VerifyMFASetupMutation(ok=False, user=user, errors=["Invalid OTP code. Please try again."])

class DisableMFAMutation(graphene.Mutation):
    class Arguments:
        # For enhanced security, you might require password or a current OTP
        # password = graphene.String(required=True)
        otp_code = graphene.String(required=True, description="A current OTP code to verify identity before disabling MFA.")

    ok = graphene.Boolean()
    user = graphene.Field(UserType, description="The user with MFA disabled.")
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, otp_code):
        user = info.context.user
        if user.is_anonymous:
            return DisableMFAMutation(ok=False, errors=["User is not authenticated."])

        if not user.mfa_enabled or not user.mfa_secret or not user.mfa_setup_complete:
            return DisableMFAMutation(ok=False, user=user, errors=["MFA is not currently enabled or setup is incomplete."])
        
        # Verify OTP before disabling
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(otp_code):
            return DisableMFAMutation(ok=False, user=user, errors=["Invalid OTP code. MFA not disabled."])

        user.mfa_enabled = False
        user.mfa_secret = None # Clear the secret
        user.mfa_setup_complete = False
        user.save(update_fields=['mfa_enabled', 'mfa_secret', 'mfa_setup_complete'])
        return DisableMFAMutation(ok=True, user=user)


class LoginWithGoogleMutation(graphene.Mutation):
    """Logs in a user using their Google account."""
    class Arguments:
        id_token = graphene.String(required=True, description="Google OAuth ID token.")
        organization_id = graphene.UUID(required=False, name="organizationId", description="Optional: ID of the organization to log into.")

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, id_token, organization_id=None):
        logger = logging.getLogger(__name__)
        logger.info("LoginWithGoogleMutation: Processing Google OAuth authentication with ID token")

        # Ensure we have a proper HttpRequest object
        request = info.context
        if not isinstance(request, HttpRequest):
            logger.warning("LoginWithGoogleMutation: info.context is not an HttpRequest. Creating a basic one.")
            request = HttpRequest()
            if not hasattr(request, 'session'):
                from django.contrib.sessions.backends.db import SessionStore
                request.session = SessionStore()
            if not hasattr(request, 'user') or not request.user:
                from django.contrib.auth.models import AnonymousUser
                request.user = AnonymousUser()

        try:
            # 1. Validate the ID token with Google
            google_client_id = getattr(settings, 'GOOGLE_CLIENT_ID', None)
            if not google_client_id:
                logger.error("LoginWithGoogleMutation: GOOGLE_CLIENT_ID setting is not configured.")
                return LoginWithGoogleMutation(errors=["Server configuration error: Google Client ID not set."])

            try:
                # Use Google's tokeninfo endpoint to validate the ID token
                response = requests.get(f'https://oauth2.googleapis.com/tokeninfo?id_token={id_token}')
                
                if response.status_code != 200:
                    logger.error(f"LoginWithGoogleMutation: Failed to validate ID token: {response.text}")
                    return LoginWithGoogleMutation(errors=["Invalid Google ID token."])
                
                token_info = response.json()
                logger.info(f"LoginWithGoogleMutation: ID Token info retrieved: {token_info}")

                # Verify the audience claim
                if token_info.get('aud') != google_client_id:
                    logger.error(f"LoginWithGoogleMutation: ID token audience mismatch. Expected {google_client_id}, got {token_info.get('aud')}")
                    return LoginWithGoogleMutation(errors=["ID token audience mismatch."])

                # Verify the issuer
                issuer = token_info.get('iss')
                if issuer not in ['accounts.google.com', 'https://accounts.google.com']:
                    logger.error(f"LoginWithGoogleMutation: Invalid ID token issuer: {issuer}")
                    return LoginWithGoogleMutation(errors=["Invalid ID token issuer."])
                
                # Extract user information
                google_user_id = token_info.get('sub')
                email = token_info.get('email')
                
                if not email:
                    logger.error("LoginWithGoogleMutation: Email not found in Google ID token")
                    return LoginWithGoogleMutation(errors=["Email not found in Google ID token."])
                
                if not token_info.get('email_verified', False):
                    logger.warning(f"LoginWithGoogleMutation: Email {email} not verified with Google")
                    return LoginWithGoogleMutation(errors=["Email not verified with Google."])
                
            except requests.RequestException as e:
                logger.error(f"LoginWithGoogleMutation: Error validating Google ID token: {str(e)}")
                return LoginWithGoogleMutation(errors=["Error validating Google ID token."])
            except Exception as e:
                logger.error(f"LoginWithGoogleMutation: Unexpected error validating ID token: {str(e)}")
                return LoginWithGoogleMutation(errors=[f"Error validating ID token: {str(e)}"])

            # 2. Find or create the user account
            email_verified = token_info.get('email_verified', False)
            # Google ID tokens might provide 'name', 'given_name', 'family_name'.
            # Prefer specific ones if available, fall back to 'name' if needed.
            given_name = token_info.get('given_name', '')
            family_name = token_info.get('family_name', '')
            if not given_name and not family_name and token_info.get('name'):
                name_parts = token_info.get('name').split(' ', 1)
                given_name = name_parts[0]
                if len(name_parts) > 1:
                    family_name = name_parts[1]
            
            if not google_user_id or not email:
                logger.error("LoginWithGoogleMutation: Missing required user data in token")
                return LoginWithGoogleMutation(errors=["Could not retrieve user information from Google"])
            
            # 4. Find or create the user account
            try:
                # Try to find existing social account
                social_account = SocialAccount.objects.get(provider='google', uid=google_user_id)
                user = social_account.user
                logger.info(f"LoginWithGoogleMutation: Found existing social account for user {user.email}")
                
                # Update the extra_data
                social_account.extra_data = token_info
                social_account.save()
            except SocialAccount.DoesNotExist:
                # Check if user with this email exists
                try:
                    user = User.objects.get(email=email)
                    logger.info(f"LoginWithGoogleMutation: Found existing user with email {email}")
                    
                    # Create social account for existing user
                    SocialAccount.objects.create(
                        user=user,
                        provider='google',
                        uid=google_user_id,
                        extra_data=token_info
                    )
                except User.DoesNotExist:
                    # Create new user
                    logger.info(f"LoginWithGoogleMutation: Creating new user with email {email}")
                    
                    user = User(
                        email=email,
                        first_name=given_name,
                        last_name=family_name,
                        is_active=True if email_verified else False
                    )
                    user.set_unusable_password()
                    user.save()
                    
                    # Create social account for new user
                    SocialAccount.objects.create(
                        user=user,
                        provider='google',
                        uid=google_user_id,
                        extra_data=token_info
                    )
            
            # 5. Check if user is active
            if not user.is_active:
                logger.warning(f"LoginWithGoogleMutation: User {user.email} is not active")
                return LoginWithGoogleMutation(errors=["User account is not active"])
            
            # 6. Log the user in
            from django.contrib.auth import login
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            
            # 7. Update last_login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # 8. Create JWT tokens
            access_token_str, _ = create_token(user.id, token_type='access')
            refresh_token_str, refresh_expires_at = create_token(user.id, token_type='refresh')
            
            # 9. Save refresh token
            RefreshToken.objects.create(
                user=user,
                token=refresh_token_str,
                expires_at=refresh_expires_at
            )
            
            logger.info(f"LoginWithGoogleMutation: Successfully authenticated user {user.email}")
            
            # 10. Handle organization context if provided
            org_context_instance = None
            mutation_errors = []
            
            if organization_id:
                logger.info(f"LoginWithGoogleMutation: Retrieving organization context for org_id: {organization_id}")
                org_service_url = getattr(settings, 'ORGANIZATION_SERVICE_URL', None)
                if not org_service_url:
                    mutation_errors.append("Organization service URL is not configured.")
                else:
                    query = """
                        query GetMembershipDetails($userId: String!, $organizationId: String!) {
                            organizationMembership(where: { userId_organizationId: { userId: $userId, organizationId: $organizationId }}) {
                                isActive
                                role
                                organization {
                                    id
                                    name
                                    slug
                                }
                            }
                        }
                    """
                    variables = {
                        "userId": str(user.id),
                        "organizationId": str(organization_id)
                    }
                    try:
                        response = requests.post(
                            org_service_url,
                            json={'query': query, 'variables': variables},
                            headers={'Content-Type': 'application/json'}
                        )
                        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                        
                        data = response.json()
                        
                        if data.get("errors"):
                            for error in data.get("errors", []):
                                mutation_errors.append(f"Organization service error: {error.get('message', 'Unknown error')}")
                        elif data.get("data") and data["data"].get("organizationMembership"):
                            membership = data["data"]["organizationMembership"]
                            if membership.get("isActive"):
                                org_details = membership.get("organization")
                                if org_details:
                                    org_context_instance = OrganizationContextType(
                                        id=org_details.get("id"),
                                        name=org_details.get("name"),
                                        slug=org_details.get("slug"),
                                        user_role_in_org=membership.get("role")
                                    )
                                else:
                                    mutation_errors.append("Organization details not found in membership.")
                            else:
                                mutation_errors.append("User membership in the specified organization is not active.")
                        else:
                            mutation_errors.append("User not found in the specified organization or membership is inactive.")
                            
                    except requests.exceptions.RequestException as e:
                        mutation_errors.append(f"Could not connect to organization service: {str(e)}")
                    except ValueError: # Includes JSONDecodeError
                        mutation_errors.append("Invalid response from organization service.")
            
            # 11. Create auth payload with organization context
            auth_payload_instance = AuthPayloadType(
                user=user,
                access_token=access_token_str,
                refresh_token=refresh_token_str,
                organization_context=org_context_instance
            )
            
            # If there were errors fetching org context, but login itself was successful,
            # we still return the auth_payload, but include the errors.
            if mutation_errors:
                return LoginWithGoogleMutation(auth_payload=auth_payload_instance, errors=mutation_errors)
            
            # 12. Return auth payload
            return LoginWithGoogleMutation(auth_payload=auth_payload_instance, errors=None)
            
        except Exception as e:
            logger.exception(f"LoginWithGoogleMutation: Unexpected error: {e}")
            return LoginWithGoogleMutation(errors=[f"An unexpected error occurred: {str(e)}"])

class UserMutation(graphene.ObjectType):
    register = RegisterMutation.Field()
    login = LoginMutation.Field()
    refresh_token = RefreshTokenMutation.Field()
    logout = LogoutMutation.Field()
    update_profile = UpdateProfileMutation.Field()
    change_password = ChangePasswordMutation.Field()
    initiate_mfa_setup = InitiateMFASetupMutation.Field(description="Initiates the MFA setup process for the authenticated user.")
    verify_mfa_setup = VerifyMFASetupMutation.Field(description="Verifies the OTP code and enables MFA for the user.")
    disable_mfa = DisableMFAMutation.Field(description="Disables MFA for the authenticated user after verification.")
    login_with_google = LoginWithGoogleMutation.Field(description="Logs in or registers a user using a Google ID Token.")

# If you were to test users/schema.py in isolation (not recommended for complex projects):
# schema = graphene.Schema(query=UserQuery, mutation=UserMutation) 