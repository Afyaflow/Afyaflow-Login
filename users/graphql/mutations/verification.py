import graphene
import logging
from django.utils import timezone
from graphql import GraphQLError

from ..types import AuthPayloadType
from ...models import User
from ...otp_utils import generate_otp, set_user_otp, verify_otp
from ...communication_client import send_templated_email
from ..services import create_auth_payload

logger = logging.getLogger(__name__)

class VerifyEmailMutation(graphene.Mutation):
    """
    Verifies the user's email address using an OTP.
    """
    class Arguments:
        otp_code = graphene.String(required=True)

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, otp_code):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in to verify your email.")

        if user.email_verified:
            return cls(auth_payload=None, errors=["Email is already verified."])

        if not verify_otp(otp_code, user, purpose='email_verification'):
             return cls(auth_payload=None, errors=["Invalid or expired OTP."])

        user.email_verified = True
        user.mfa_otp = None
        user.mfa_otp_expires_at = None
        user.mfa_otp_purpose = None
        user.save(update_fields=['email_verified', 'mfa_otp', 'mfa_otp_expires_at', 'mfa_otp_purpose'])

        # Also update the allauth EmailAddress model for consistency
        from allauth.account.models import EmailAddress
        try:
            email_address = EmailAddress.objects.get(user=user, email=user.email)
            email_address.verified = True
            email_address.save(update_fields=['verified'])
        except EmailAddress.DoesNotExist:
            # Create it if it doesn't exist (shouldn't happen, but safety net)
            EmailAddress.objects.create(
                user=user,
                email=user.email,
                primary=True,
                verified=True
            )

        logger.info(f"Email address successfully verified for user {user.email}.")

        # Return a full auth payload so the frontend can seamlessly transition.
        auth_data = create_auth_payload(user)
        auth_payload_instance = AuthPayloadType(**auth_data)
        
        return cls(auth_payload=auth_payload_instance, errors=None)


class ResendVerificationEmailMutation(graphene.Mutation):
    """
    Resends the email verification OTP to the logged-in user's email address.
    """
    class Arguments:
        pass

    ok = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in to perform this action.")

        if user.email_verified:
            return cls(ok=False, errors=["Your email is already verified."])

        # Generate and send a new OTP
        otp = generate_otp()
        set_user_otp(user, otp, purpose='email_verification')

        try:
            context = {"first_name": user.first_name or "user", "otp_code": otp}
            email_sent = send_templated_email(
                recipient=user.email,
                template_id='email_verification', # Assumes this template exists
                context=context
            )
            if not email_sent:
                logger.error(f"Failed to resend verification email to {user.email}.")
                return cls(ok=False, errors=["Failed to send email. Please try again later."])
        except Exception as e:
            logger.error(f"An unexpected error occurred trying to resend verification email for {user.email}: {e}")
            return cls(ok=False, errors=["An unexpected error occurred. Please try again later."])

        logger.info(f"Verification email resent to {user.email}.")
        return cls(ok=True, message="A new verification code has been sent to your email address.") 