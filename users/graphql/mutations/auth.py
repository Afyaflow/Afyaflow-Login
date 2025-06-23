import graphene
import logging
from django.db import transaction
from django.contrib.auth import authenticate, login as django_login
from django.conf import settings
from django.utils import timezone
from graphql import GraphQLError

from ..types import AuthPayloadType, OrganizationStub, MfaChallengeType, LoginPayload, ScopedAuthPayload, GetScopedAccessTokenPayload
from ..services import create_auth_payload, get_user_organization_memberships
from ...models import RefreshToken, User
from ...serializers import UserRegistrationSerializer
from ...authentication import create_token, JWTAuthentication, create_oct_token
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
        
        # Send a verification OTP to the user's email
        try:
            otp = generate_otp()
            set_user_otp(user, otp, purpose='email_verification') # Saves the hashed OTP and expiry to the user model

            context = {
                "first_name": user.first_name or "there",
                "otp_code": otp
            }
            email_sent = send_templated_email(
                recipient=user.email,
                template_id='email_verification', # Assumes this template exists
                context=context
            )
            if not email_sent:
                # Log a warning but don't fail the registration. The user can request another OTP.
                logger.warning(f"Failed to send verification email to {user.email}, but registration will proceed.")
        except Exception as e:
            logger.error(f"An unexpected error occurred trying to send verification email for {user.email}: {e}")

        logger.info(f"User {email} registered successfully. A verification OTP has been sent.")
        
        auth_data = create_auth_payload(user)
        auth_payload_instance = AuthPayloadType(**auth_data)
        
        return RegisterMutation(auth_payload=auth_payload_instance, errors=None)

class LoginMutation(graphene.Mutation):
    """
    Logs in a user. Returns an authentication payload which may indicate
    that a second MFA step is required to complete the login.
    """
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, email, password):
        user = authenticate(email=email, password=password)
        if not user:
            logger.warning(f"Login failed for email {email}: Invalid credentials.")
            return LoginMutation(auth_payload=None, errors=["Invalid credentials."])
        
        if user.is_suspended:
            reason = getattr(user, 'suspension_reason', 'No reason provided.')
            logger.warning(f"Login failed for email {email}: Account suspended. Reason: {reason}")
            return LoginMutation(auth_payload=None, errors=[f"Account is suspended. Reason: {reason}"])

        # Check which MFA methods are active
        enabled_methods = []
        if user.mfa_totp_setup_complete: enabled_methods.append("TOTP")
        if user.mfa_email_enabled: enabled_methods.append("EMAIL")
        if user.mfa_sms_enabled and user.phone_number_verified: enabled_methods.append("SMS")

        is_mfa_active = bool(enabled_methods)

        if not is_mfa_active:
            # No MFA enabled, return the full auth payload with tokens.
            auth_data = create_auth_payload(user, mfa_required=False)
            return LoginMutation(auth_payload=AuthPayloadType(**auth_data))

        # MFA is active, so we start the two-step challenge.
        
        # 1. Send OTPs if Email or SMS MFA are enabled.
        if "EMAIL" in enabled_methods or "SMS" in enabled_methods:
            otp = generate_otp()
            set_user_otp(user, otp)

            message_context = f"Your AfyaFlow verification code is: {otp}"
            if "EMAIL" in enabled_methods:
                send_templated_email(
                    recipient=user.email,
                    template_id='mfa_otp', # Assumes this template exists
                    context={"first_name": user.first_name or "user", "otp_code": otp}
                )
            if "SMS" in enabled_methods:
                send_sms(recipient=user.phone_number, message=message_context)

        # 2. Create a short-lived MFA token.
        mfa_token, _ = create_token(user.id, token_type='mfa')

        # 3. Return the challenge payload to the client (without access/refresh tokens).
        challenge_payload = AuthPayloadType(
            user=user,
            mfa_required=True,
            mfa_token=mfa_token,
            enabled_mfa_methods=enabled_methods,
        )
        logger.info(f"MFA challenge issued for user {user.email}.")
        return LoginMutation(auth_payload=challenge_payload)

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
                if verify_otp(otp_code, user):
                    is_valid = True
                    # Invalidate the one-time code immediately after use
                    user.mfa_otp = None
                    user.mfa_otp_expires_at = None
                    user.save(update_fields=['mfa_otp', 'mfa_otp_expires_at'])

        if not is_valid:
            logger.warning(f"MFA verification failed for user {user.email}: Invalid OTP code.")
            return cls(auth_payload=None, errors=["Invalid OTP code."])

        # 4. Success! Log the user in and return the full auth payload.
        django_login(info.context, user, backend='django.contrib.auth.backends.ModelBackend')
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

class GetScopedAccessToken(graphene.Mutation):
    """
    Given a valid identity token and an organization ID, returns an
    Organization Context Token (OCT) scoped with that organization's permissions.
    """
    class Arguments:
        organization_id = graphene.UUID(required=True, name="organizationId")

    payload = graphene.Field(GetScopedAccessTokenPayload)
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, organization_id):
        # 1. User must be authenticated
        user = info.context.user
        if not user.is_authenticated:
            return cls(payload=None, errors=["You must be logged in to perform this action."])

        # 2. Verify user is a member of the requested organization
        memberships = get_user_organization_memberships(user.id)
        org_ids = [
            str(membership.get('organization', {}).get('id'))
            for membership in memberships
            if membership.get('organization')
        ]

        if str(organization_id) not in org_ids:
            logger.warning(f"Security risk: User {user.id} attempted to get OCT for org {organization_id} they are not a member of.")
            return cls(payload=None, errors=["You do not have permission to access this organization."])

        # 3. Create the Organization Context Token (OCT)
        oct_token_str, _ = create_oct_token(user.id, organization_id)
        logger.info(f"Successfully created OCT for user {user.email} in organization {organization_id}")

        # 4. Construct the payload
        scoped_payload = ScopedAuthPayload(
            oct=oct_token_str,
            user=user
        )
        
        return cls(payload=scoped_payload)
