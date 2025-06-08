import graphene
import logging
from django.db import transaction
from django.contrib.auth import authenticate, login as django_login
from django.conf import settings
from django.utils import timezone

from ..types import AuthPayloadType, OrganizationStub
from ..services import create_auth_payload, GoogleAuthService
from ...models import RefreshToken, User
from ...serializers import UserRegistrationSerializer

logger = logging.getLogger(__name__)

class RegisterMutation(graphene.Mutation):
    """Registers a new user in the system."""
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)
        password_confirm = graphene.String(required=True)
        first_name = graphene.String()
        last_name = graphene.String()

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, email, password, password_confirm, first_name=None, last_name=None):
        serializer = UserRegistrationSerializer(data={
            'email': email,
            'password': password,
            'password_confirm': password_confirm,
            'first_name': first_name,
            'last_name': last_name
        })
        
        if not serializer.is_valid():
            errors = [f"{field}: {message}" for field, messages in serializer.errors.items() for message in messages]
            logger.warning(f"User registration failed for email {email}: {errors}")
            return RegisterMutation(auth_payload=None, errors=errors)
        
        user = serializer.save()
        logger.info(f"User {email} registered successfully.")
        
        auth_data = create_auth_payload(user)
        auth_payload_instance = AuthPayloadType(**auth_data)
        
        return RegisterMutation(auth_payload=auth_payload_instance, errors=None)

class LoginMutation(graphene.Mutation):
    """Logs in an existing user."""
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)
        organization_id = graphene.UUID(required=False, name="organizationId")
        mfa_code = graphene.String(required=False, name="mfaCode")

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, email, password, organization_id=None, mfa_code=None):
        user = authenticate(email=email, password=password)
        if not user:
            logger.warning(f"Login failed for email {email}: Invalid credentials.")
            return LoginMutation(auth_payload=None, errors=["Invalid credentials."])
        
        if user.is_suspended:
            reason = getattr(user, 'suspension_reason', 'No reason provided.')
            logger.warning(f"Login failed for email {email}: Account suspended. Reason: {reason}")
            return LoginMutation(auth_payload=None, errors=[f"Account is suspended. Reason: {reason}"])

        # MFA Check
        if user.mfa_enabled and user.mfa_setup_complete:
            if not mfa_code:
                return LoginMutation(auth_payload=None, errors=["MFA code is required."])
            import pyotp
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(mfa_code):
                logger.warning(f"Login failed for email {email}: Invalid MFA code.")
                return LoginMutation(auth_payload=None, errors=["Invalid MFA code."])

        # Log user into Django session
        django_login(info.context, user)
        logger.info(f"User {email} logged in successfully.")
        
        auth_data = create_auth_payload(user, organization_id=organization_id)
        org_context_instance = OrganizationStub(id=organization_id) if organization_id else None
        
        auth_payload_instance = AuthPayloadType(
            **auth_data,
            organization_context=org_context_instance
        )
        
        return LoginMutation(auth_payload=auth_payload_instance, errors=None)

class RefreshTokenMutation(graphene.Mutation):
    """Refreshes a user's access token."""
    class Arguments:
        refresh_token = graphene.String(required=True)

    access_token = graphene.String()
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, refresh_token):
        try:
            token_obj = RefreshToken.objects.get(
                token=refresh_token,
                expires_at__gt=timezone.now(),
                is_revoked=False
            )
            
            from ...authentication import create_token
            new_access_token_str, _ = create_token(token_obj.user.id, token_type='access')
            logger.info(f"Access token refreshed for user {token_obj.user.email}")
            return RefreshTokenMutation(access_token=new_access_token_str, errors=None)
            
        except RefreshToken.DoesNotExist:
            logger.warning("Refresh token mutation failed: Invalid or expired refresh token.")
            return RefreshTokenMutation(access_token=None, errors=["Invalid or expired refresh token."])

class LogoutMutation(graphene.Mutation):
    """Logs out a user by revoking their refresh token."""
    class Arguments:
        refresh_token = graphene.String(required=True)

    ok = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, refresh_token):
        try:
            token_obj = RefreshToken.objects.get(token=refresh_token, is_revoked=False)
            token_obj.is_revoked = True
            token_obj.save()
            logger.info(f"User {token_obj.user.email} logged out successfully.")
            return LogoutMutation(ok=True, errors=None)
        except RefreshToken.DoesNotExist:
            logger.warning("Logout failed: Invalid or already revoked refresh token.")
            return LogoutMutation(ok=False, errors=["Invalid or already revoked refresh token."])

class LoginWithGoogleMutation(graphene.Mutation):
    """Logs in a user using their Google account."""
    class Arguments:
        id_token = graphene.String(required=True)
        organization_id = graphene.UUID(required=False, name="organizationId")

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, id_token, organization_id=None):
        try:
            google_auth = GoogleAuthService(id_token)
            token_info = google_auth.validate_token()
            user = google_auth.get_or_create_user(token_info)

            if not user.is_active:
                logger.warning(f"Google login failed for {user.email}: User account is not active.")
                return LoginWithGoogleMutation(errors=["User account is not active."])
            
            # Log user into Django session
            django_login(info.context, user, backend='django.contrib.auth.backends.ModelBackend')
            
            auth_data = create_auth_payload(user, organization_id=organization_id)
            org_context_instance = OrganizationStub(id=organization_id) if organization_id else None
            
            auth_payload_instance = AuthPayloadType(
                **auth_data,
                organization_context=org_context_instance
            )
            
            logger.info(f"Google login successful for user {user.email}")
            return LoginWithGoogleMutation(auth_payload=auth_payload_instance, errors=None)

        except ValueError as e:
            logger.error(f"Google login failed: {e}")
            return LoginWithGoogleMutation(errors=[str(e)])
        except Exception as e:
            logger.exception(f"An unexpected error occurred during Google login: {e}")
            return LoginWithGoogleMutation(errors=[f"An unexpected error occurred: {str(e)}"])
