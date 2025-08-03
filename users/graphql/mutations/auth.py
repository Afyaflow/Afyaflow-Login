import graphene
import logging
from django.db import transaction
from django.contrib.auth import authenticate, login as django_login
from django.conf import settings
from django.utils import timezone
from graphql import GraphQLError

from ..types import AuthPayloadType, OrganizationStub, MfaChallengeType, LoginPayload, ScopedAuthPayload, GetScopedAccessTokenPayload
from ..services import create_auth_payload, get_user_organization_memberships, get_user_organization_roles
from ...models import RefreshToken, User, AuthenticationAttempt
from ...serializers import UserRegistrationSerializer
from ...authentication import create_token, JWTAuthentication, create_oct_token
from ...communication_client import send_templated_email, send_sms
from ...otp_utils import generate_otp, set_user_otp, verify_otp
from ...security_middleware import auth_attempt_tracker
from .mfa import get_recommended_mfa_method
import pyotp

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Get the real client IP address."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip

class RegisterMutation(graphene.Mutation):
    """Registers a new user in the system."""
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)
        password_confirm = graphene.String(required=True)
        first_name = graphene.String(required=True)
        last_name = graphene.String(required=True)

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, email, password, password_confirm, first_name, last_name):
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

        # Create EmailAddress record for allauth consistency
        from allauth.account.models import EmailAddress
        EmailAddress.objects.create(
            user=user,
            email=user.email,
            primary=True,
            verified=False  # Will be verified when user completes email verification
        )

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
        # Get client information for security tracking
        client_ip = get_client_ip(info.context)
        user_agent = info.context.META.get('HTTP_USER_AGENT', 'Unknown')

        # Check if IP is locked out
        if auth_attempt_tracker.is_locked_out(client_ip, 'login'):
            logger.warning(f"Login attempt from locked out IP: {client_ip}")
            return LoginMutation(auth_payload=None, errors=["Too many failed attempts. Please try again later."])

        user = authenticate(email=email, password=password)
        if not user:
            # Record failed attempt
            attempt_status = auth_attempt_tracker.record_attempt(
                client_ip, False, 'login', email, 'Invalid credentials'
            )

            # Create database record
            AuthenticationAttempt.objects.create(
                email=email,
                attempt_type='login',
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                failure_reason='Invalid credentials'
            )

            logger.warning(f"Login failed for email {email}: Invalid credentials. Attempts remaining: {attempt_status['attempts_remaining']}")
            return LoginMutation(auth_payload=None, errors=["Invalid credentials."])

        if user.is_suspended:
            reason = getattr(user, 'suspension_reason', 'No reason provided.')

            # Create failure reason and truncate if necessary
            failure_reason = AuthenticationAttempt.truncate_failure_reason(
                f'Account suspended: {reason}'
            )

            # Record failed attempt
            auth_attempt_tracker.record_attempt(
                client_ip, False, 'login', email, failure_reason
            )

            AuthenticationAttempt.objects.create(
                email=email,
                attempt_type='login',
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                failure_reason=failure_reason,
                user=user
            )

            logger.warning(f"Login failed for email {email}: Account suspended. Reason: {reason}")
            return LoginMutation(auth_payload=None, errors=[f"Account is suspended. Reason: {reason}"])

        # Check which MFA methods are active
        enabled_methods = []
        if user.mfa_totp_setup_complete: enabled_methods.append("TOTP")
        if user.mfa_email_enabled: enabled_methods.append("EMAIL")
        if user.mfa_sms_enabled and user.phone_number_verified: enabled_methods.append("SMS")

        is_mfa_active = bool(enabled_methods)

        if not is_mfa_active:
            # No MFA enabled, record successful attempt and return tokens
            auth_attempt_tracker.record_attempt(client_ip, True, 'login', email)

            AuthenticationAttempt.objects.create(
                email=email,
                attempt_type='login',
                ip_address=client_ip,
                user_agent=user_agent,
                success=True,
                user=user
            )

            auth_data = create_auth_payload(user, mfa_required=False)
            return LoginMutation(auth_payload=AuthPayloadType(**auth_data))

        # MFA is active, so we start the method selection challenge.

        # 1. Get recommended method (most secure first)
        recommended_method = get_recommended_mfa_method(enabled_methods)

        # 2. Create a short-lived MFA token with user type for gateway compliance.
        mfa_token, _ = create_token(user.id, token_type='mfa', user_type=user.user_type)

        # 3. Return the method selection challenge payload to the client (without access/refresh tokens).
        challenge_payload = AuthPayloadType(
            user=user,
            mfa_required=True,
            mfa_token=mfa_token,
            enabled_mfa_methods=enabled_methods,
            recommended_mfa_method=recommended_method,
        )
        logger.info(f"MFA method selection challenge issued for user {user.email}. Available methods: {enabled_methods}, Recommended: {recommended_method}")
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

        # 3. Check if method was selected (required for new flow)
        selected_method = payload.get('selected_mfa_method')
        if not selected_method:
            return cls(auth_payload=None, errors=["MFA method must be selected first. Please use selectMfaMethod mutation."])

        # 4. Verify the provided OTP code based on selected method
        is_valid = False

        if selected_method == "TOTP":
            # Check TOTP from authenticator app
            if user.mfa_totp_setup_complete:
                totp = pyotp.TOTP(user.mfa_totp_secret)
                if totp.verify(otp_code):
                    is_valid = True
                    logger.info(f"TOTP verification successful for user {user.email}")
                else:
                    logger.warning(f"TOTP verification failed for user {user.email}")
            else:
                return cls(auth_payload=None, errors=["TOTP MFA is not properly set up for your account."])

        elif selected_method in ["EMAIL", "SMS"]:
            # Check Email/SMS OTP with purpose validation
            if user.mfa_otp and user.mfa_otp_expires_at and timezone.now() < user.mfa_otp_expires_at:
                if verify_otp(otp_code, user, purpose='mfa_login'):
                    is_valid = True
                    logger.info(f"{selected_method} OTP verification successful for user {user.email}")
                    # Note: verify_otp already invalidates the OTP on success
                else:
                    logger.warning(f"{selected_method} OTP verification failed for user {user.email}")
            else:
                return cls(auth_payload=None, errors=["No valid OTP found. Please request a new code."])
        else:
            return cls(auth_payload=None, errors=["Invalid MFA method in token."])

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
            new_access_token_str, _ = create_token(token_obj.user.id, token_type='access', user_type=token_obj.user.user_type)
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

        # 3. Get user roles for the organization
        user_roles = get_user_organization_roles(user.id, organization_id)
        logger.info(f"Retrieved roles for user {user.email} in org {organization_id}: {user_roles}")

        # 4. Create the enhanced Organization Context Token (OCT) with user details
        oct_token_str, _ = create_oct_token(
            user_id=user.id,
            organization_id=organization_id,
            user_email=user.email,
            user_first_name=user.first_name,
            user_last_name=user.last_name,
            user_roles=user_roles
        )
        logger.info(f"Successfully created enhanced OCT for user {user.email} in organization {organization_id}")

        # 5. Construct the payload
        scoped_payload = ScopedAuthPayload(
            oct=oct_token_str,
            user=user
        )

        return cls(payload=scoped_payload)
