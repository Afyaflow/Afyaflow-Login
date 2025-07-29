import graphene
import logging
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from graphql import GraphQLError

from ..types import AuthPayloadType
from ...models import User
from ...otp_utils import generate_otp, set_user_otp, verify_otp
from ...communication_client import send_templated_email

logger = logging.getLogger(__name__)


class AddEmailMutation(graphene.Mutation):
    """
    For phone-only users to add a real email address.
    Only works for users with placeholder emails.
    """

    class Arguments:
        email = graphene.String(required=True, description="Email address to add")

    success = graphene.Boolean()
    message = graphene.String()
    verification_required = graphene.Boolean()

    @classmethod
    def mutate(cls, root, info, email):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in.")

        # Only allow this for users with placeholder emails
        if user.has_real_email:
            return cls(
                success=False,
                message="You already have a real email address.",
                verification_required=False
            )

        # Validate email
        try:
            validate_email(email)
        except ValidationError:
            return cls(
                success=False,
                message="Please enter a valid email address.",
                verification_required=False
            )

        # Check if email is taken
        if User.objects.filter(email=email).exists():
            return cls(
                success=False,
                message="This email address is already in use.",
                verification_required=False
            )

        # Send verification directly to the new email
        otp = generate_otp()
        set_user_otp(user, otp, purpose='add_email')

        try:
            email_sent = send_templated_email(
                recipient=email,
                template_id='add_email_verification',
                context={
                    'first_name': user.first_name or 'User',
                    'otp_code': otp,
                    'phone_number': user.phone_number
                }
            )

            if email_sent:
                # Store the email to be added
                user.pending_email = email
                user.save(update_fields=['pending_email'])

                logger.info(f"Add email verification sent to {email} for user {user.id}")
                return cls(
                    success=True,
                    message=f"Verification code sent to {email}. Please check your email.",
                    verification_required=True
                )
            else:
                return cls(
                    success=False,
                    message="Failed to send verification email. Please try again.",
                    verification_required=False
                )

        except Exception as e:
            logger.error(f"Failed to send add email verification: {e}")
            return cls(
                success=False,
                message="Failed to send verification email. Please try again.",
                verification_required=False
            )


class VerifyAddEmailMutation(graphene.Mutation):
    """
    Verifies OTP and adds real email for phone-only users.
    """

    class Arguments:
        otp_code = graphene.String(required=True, description="The OTP code from email")

    success = graphene.Boolean()
    message = graphene.String()
    user = graphene.Field('users.graphql.types.UserType')

    @classmethod
    def mutate(cls, root, info, otp_code):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in.")

        # Only allow for users with placeholder emails
        if user.has_real_email:
            return cls(
                success=False,
                message="You already have a real email address.",
                user=None
            )

        if not user.pending_email:
            return cls(
                success=False,
                message="No pending email addition found. Please request to add an email first.",
                user=None
            )

        # Verify OTP
        if not verify_otp(otp_code, user, purpose='add_email'):
            return cls(
                success=False,
                message="Invalid or expired verification code.",
                user=None
            )

        # Replace placeholder email with real email
        old_email = user.email
        user.email = user.pending_email
        user.pending_email = None
        user.email_verified = True
        user.save(update_fields=['email', 'pending_email', 'email_verified'])

        logger.info(f"User {user.id} added real email {user.email} (replaced placeholder {old_email})")

        return cls(
            success=True,
            message="Email address added successfully! You can now receive emails and notifications.",
            user=user
        )
