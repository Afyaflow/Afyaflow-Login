import graphene
import logging
from django.db import transaction
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q
import secrets
import re # Import the regular expressions module

from ..types import UserType
from ...models import RefreshToken, User
from ...serializers import UserProfileSerializer
from ...communication_client import send_templated_email, send_sms
from ...otp_utils import generate_otp, set_user_otp, verify_otp
from graphql import GraphQLError

logger = logging.getLogger(__name__)

class UpdateProfileMutation(graphene.Mutation):
    """Updates the profile for the authenticated user."""
    class Arguments:
        first_name = graphene.String()
        last_name = graphene.String()

    user = graphene.Field(UserType)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, first_name=None, last_name=None):
        user = info.context.user
        if user.is_anonymous:
            return UpdateProfileMutation(user=None, errors=["User is not authenticated."])

        update_data = {}
        if first_name is not None:
            update_data['first_name'] = first_name
        if last_name is not None:
            update_data['last_name'] = last_name
        
        if not update_data:
             return UpdateProfileMutation(user=user, errors=["No update data provided."])

        serializer = UserProfileSerializer(instance=user, data=update_data, partial=True)
        if serializer.is_valid():
            updated_user = serializer.save()
            logger.info(f"User {user.email} updated their profile.")
            return UpdateProfileMutation(user=updated_user, errors=None)
        else:
            errors = [f"{field}: {message}" for field, messages in serializer.errors.items() for message in messages]
            logger.warning(f"User {user.email} profile update failed: {errors}")
            return UpdateProfileMutation(user=None, errors=errors)

class ChangePasswordMutation(graphene.Mutation):
    """Changes the password for the authenticated user."""
    class Arguments:
        old_password = graphene.String(required=True)
        new_password = graphene.String(required=True)
        new_password_confirm = graphene.String(required=True)

    ok = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, old_password, new_password, new_password_confirm):
        user = info.context.user
        if user.is_anonymous:
            return ChangePasswordMutation(ok=False, errors=["User is not authenticated."])

        if new_password != new_password_confirm:
            return ChangePasswordMutation(ok=False, errors=["New passwords do not match."])

        if not user.check_password(old_password):
            logger.warning(f"User {user.email} failed to change password: Incorrect old password.")
            return ChangePasswordMutation(ok=False, errors=["Incorrect old password."])
        
        try:
            validate_password(new_password, user=user)
        except ValidationError as e:
            logger.warning(f"User {user.email} failed to change password: {e.messages}")
            return ChangePasswordMutation(ok=False, errors=e.messages)

        user.set_password(new_password)
        user.save()

        # Revoke all refresh tokens for the user upon password change
        RefreshToken.objects.filter(user=user).update(is_revoked=True)
        logger.info(f"User {user.email} changed their password successfully.")

        return ChangePasswordMutation(ok=True, errors=None)

class InitiatePasswordResetMutation(graphene.Mutation):
    """
    Initiates the password reset process by sending an OTP to the user's
    email and/or verified phone number.
    """
    class Arguments:
        email_or_phone = graphene.String(required=True)

    ok = graphene.Boolean()
    message = graphene.String()

    @classmethod
    def mutate(cls, root, info, email_or_phone):
        # Determine if the input is an email or a phone number
        is_email = re.match(r"[^@]+@[^@]+\.[^@]+", email_or_phone)
        
        try:
            if is_email:
                user = User.objects.get(email__iexact=email_or_phone)
            else:
                user = User.objects.get(phone_number=email_or_phone)
        except User.DoesNotExist:
            logger.warning(f"Password reset initiated for non-existent user: {email_or_phone}")
            return cls(ok=True, message="If an account with this email or phone number exists, a password reset code has been sent.")

        otp = generate_otp()
        set_user_otp(user, otp, purpose='password_reset')

        # Send the OTP to the selected channel only
        if is_email:
            try:
                send_templated_email(
                    recipient=user.email,
                    template_id='password_reset_otp',
                    context={"first_name": user.first_name or "user", "otp_code": otp}
                )
                logger.info(f"Password reset OTP sent to email for user {user.email}.")
            except Exception as e:
                logger.error(f"Failed to send password reset email for {user.email}: {e}")
                raise GraphQLError("Failed to send the password reset code. Please try again later.")
        else: # It's a phone number
            if user.phone_number_verified:
                try:
                    message = f"Your AfyaFlow password reset code is: {otp}"
                    send_sms(recipient=user.phone_number, message=message)
                    logger.info(f"Password reset OTP sent to phone for user {user.email}.")
                except Exception as e:
                    logger.error(f"Failed to send password reset SMS for {user.email}: {e}")
                    raise GraphQLError("Failed to send the password reset code. Please try again later.")
            else:
                # Don't send if the phone number isn't verified, but don't reveal that either.
                logger.warning(f"Password reset attempted for user {user.email} with unverified phone number.")
        
        return cls(ok=True, message="If an account with this email or phone number exists, a password reset code has been sent.")

class ResetPasswordWithOtpMutation(graphene.Mutation):
    """
    Completes the password reset process using a valid OTP.
    """
    class Arguments:
        email_or_phone = graphene.String(required=True)
        otp_code = graphene.String(required=True)
        new_password = graphene.String(required=True)
        new_password_confirm = graphene.String(required=True)

    ok = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, email_or_phone, otp_code, new_password, new_password_confirm):
        if new_password != new_password_confirm:
            return cls(ok=False, errors=["Passwords do not match."])

        try:
            user = User.objects.get(
                Q(email__iexact=email_or_phone) | Q(phone_number=email_or_phone)
            )
        except User.DoesNotExist:
            return cls(ok=False, errors=["Invalid OTP or user not found."])

        if not verify_otp(otp_code, user, purpose='password_reset'):
            return cls(ok=False, errors=["Invalid or expired OTP code."])

        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return cls(ok=False, errors=list(e.messages))

        user.set_password(new_password)
        
        # Invalidate the reset OTP
        user.mfa_otp = None
        user.mfa_otp_expires_at = None
        user.mfa_otp_purpose = None
        user.save()

        # Also revoke all refresh tokens for security
        RefreshToken.objects.filter(user=user).update(is_revoked=True)

        # Send a confirmation email that the password has changed
        try:
            send_templated_email(
                recipient=user.email,
                template_id='password_changed_notification', # New template
                context={"first_name": user.first_name or "user"}
            )
            logger.info(f"Sent password change notification to user {user.email}.")
        except Exception as e:
            logger.error(f"Failed to send password change notification to {user.email}: {e}")
            # Do not fail the whole mutation if this email fails
        
        logger.info(f"Password reset successfully for user {user.email}.")
        return cls(ok=True)
