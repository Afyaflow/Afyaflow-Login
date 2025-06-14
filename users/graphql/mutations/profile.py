import graphene
import logging
from django.db import transaction
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
import secrets

from ..types import UserType
from ...models import RefreshToken, User
from ...serializers import UserProfileSerializer
from ...communication_client import send_templated_email

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
    Initiates the password reset process for a user by generating a token
    and sending it to their email.
    """
    class Arguments:
        email = graphene.String(required=True)

    ok = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, email):
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Don't reveal that the user does not exist.
            # Return a success-like message to prevent user enumeration.
            logger.warning(f"Password reset initiated for non-existent email: {email}")
            return InitiatePasswordResetMutation(ok=True, message="If an account with this email exists, a password reset link has been sent.")

        # Generate a secure, URL-safe token
        token = secrets.token_urlsafe(32)
        
        # Set token and expiry on the user model (e.g., valid for 10 minutes)
        user.password_reset_token = token
        user.password_reset_token_expires_at = timezone.now() + timedelta(minutes=10)
        user.save()

        # Send the password reset email
        try:
            context = {"first_name": user.first_name or "user", "reset_token": token}
            email_sent = send_templated_email(
                recipient=user.email,
                template_id='password_reset',
                context=context
            )
            if not email_sent:
                logger.error(f"Failed to send password reset email to {user.email}.")
                return InitiatePasswordResetMutation(ok=False, errors=["Failed to send email. Please try again later."])
        except Exception as e:
            logger.error(f"An unexpected error occurred trying to send password reset email for {user.email}: {e}")
            return InitiatePasswordResetMutation(ok=False, errors=["An unexpected error occurred. Please try again later."])

        logger.info(f"Password reset token sent to {email}.")
        return InitiatePasswordResetMutation(ok=True, message="If an account with this email exists, a password reset link has been sent.")
