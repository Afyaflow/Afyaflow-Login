import graphene
import logging
from django.db import transaction
from django.contrib.auth import authenticate, login as django_login
from django.conf import settings
from django.utils import timezone
from graphql import GraphQLError

from ..types import AuthPayloadType, OrganizationStub, MfaChallengeType, LoginPayload
from ..services import GoogleAuthService, create_auth_payload
from ...models import RefreshToken, User
from ...serializers import UserRegistrationSerializer
from ...authentication import create_token, JWTAuthentication
from ...communication_client import send_templated_email, send_sms
from ...otp_utils import generate_otp, set_user_otp, verify_otp
import pyotp

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
        
        # Send welcome email
        try:
            context = {"first_name": user.first_name or "there"}
            email_sent = send_templated_email(
                recipient=user.email,
                template_id='user_registration',
                context=context
            )
            if not email_sent:
                logger.warning(f"Failed to send welcome email to {user.email}, but registration will proceed.")
        except Exception as e:
            logger.error(f"An unexpected error occurred trying to send welcome email for {user.email}: {e}")

        logger.info(f"User {email} registered successfully.")
        
        auth_data = create_auth_payload(user)
        auth_payload_instance = AuthPayloadType(**auth_data)
        
        return RegisterMutation(auth_payload=auth_payload_instance, errors=None)

class LoginMutation(graphene.Mutation):
    """
    Logs in a user. This is the first step of a potential two-step MFA flow.
    Returns either a full authentication payload or an MFA challenge.
    """
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)

    payload = graphene.Field(LoginPayload)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, email, password):
        user = authenticate(email=email, password=password)
        if not user:
            logger.warning(f"Login failed for email {email}: Invalid credentials.")
            return LoginMutation(payload=None, errors=["Invalid credentials."])
        
        if user.is_suspended:
            reason = getattr(user, 'suspension_reason', 'No reason provided.')
            logger.warning(f"Login failed for email {email}: Account suspended. Reason: {reason}")
            return LoginMutation(payload=None, errors=[f"Account is suspended. Reason: {reason}"])

        # Check if any MFA method is active
        is_mfa_active = user.mfa_totp_setup_complete or user.mfa_email_enabled or user.mfa_sms_enabled

        if not is_mfa_active:
            # No MFA enabled, log the user in directly.
            auth_data = create_auth_payload(user)
            return LoginMutation(payload=AuthPayloadType(**auth_data))

        # MFA is active, so we start the two-step challenge.
        
        # 1. Send OTPs if Email or SMS MFA are enabled.
        if user.mfa_email_enabled or user.mfa_sms_enabled:
            otp = generate_otp()
            set_user_otp(user, otp)  # Hashes and saves OTP to the user model
            
            message_context = f"Your AfyaFlow verification code is: {otp}"
            if user.mfa_email_enabled:
                send_templated_email(
                    recipient=user.email,
                    template_id='mfa_otp',
                    context={"first_name": user.first_name or "user", "otp_code": otp}
                )
            if user.mfa_sms_enabled and user.phone_number_verified:
                send_sms(recipient=user.phone_number, message=message_context)

        # 2. Create a short-lived MFA token.
        mfa_token, _ = create_token(user.id, token_type='mfa')

        # 3. Return the MFA challenge to the client.
        challenge = MfaChallengeType(
            mfa_token=mfa_token,
            message="MFA is required. Please submit an OTP to complete login."
        )
        logger.info(f"MFA challenge issued for user {user.email}.")
        return LoginMutation(payload=challenge)

class VerifyMfaMutation(graphene.Mutation):
    """
    Verifies an OTP code using a short-lived MFA token to complete the login process.
    """
    class Arguments:
        mfa_token = graphene.String(required=True)
        otp_code = graphene.String(required=True)

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, mfa_token, otp_code):
        # 1. Validate the MFA token
        jwt_authenticator = JWTAuthentication()
        try:
            user, payload = jwt_authenticator.authenticate_mfa_token(mfa_token)
        except Exception as e:
            return cls(auth_payload=None, errors=[str(e)])

        # 2. Check if the token was for MFA
        if payload.get('type') != 'mfa':
            return cls(auth_payload=None, errors=["Invalid token type provided."])

        # 3. Verify the provided OTP code
        is_valid = False
        
        # Check TOTP from authenticator app
        if user.mfa_totp_setup_complete:
            totp = pyotp.TOTP(user.mfa_totp_secret)
            if totp.verify(otp_code):
                is_valid = True

        # If not valid yet, check Email/SMS OTP
        if not is_valid and (user.mfa_email_enabled or user.mfa_sms_enabled):
            if user.mfa_otp and user.mfa_otp_expires_at and timezone.now() < user.mfa_otp_expires_at:
                if verify_otp(otp_code, user.mfa_otp):
                    is_valid = True
                    # Invalidate the one-time code immediately after use
                    user.mfa_otp = None
                    user.mfa_otp_expires_at = None
                    user.save(update_fields=['mfa_otp', 'mfa_otp_expires_at'])

        if not is_valid:
            logger.warning(f"MFA verification failed for user {user.email}: Invalid OTP code.")
            return cls(auth_payload=None, errors=["Invalid OTP code."])

        # 4. Success! Log the user in and return the full auth payload.
        django_login(info.context, user)
        logger.info(f"User {user.email} successfully completed MFA and logged in.")
        auth_data = create_auth_payload(user)
        return cls(auth_payload=AuthPayloadType(**auth_data))

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
