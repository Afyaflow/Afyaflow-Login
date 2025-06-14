import graphene
import logging
from django.contrib.auth import update_session_auth_hash
from graphql import GraphQLError
from ..types import UserType
from ...models import User, RefreshToken
from ..services import send_templated_email
import secrets
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


class UpdateProfileMutation(graphene.Mutation):
    """
    Updates the profile for the currently authenticated user.
    """
    class Arguments:
        first_name = graphene.String()
        last_name = graphene.String()

    user = graphene.Field(UserType)
    errors = graphene.List(graphene.String)

    @staticmethod
    def mutate(root, info, **kwargs):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in to update your profile.")

        # Update specified fields
        if 'first_name' in kwargs:
            user.first_name = kwargs['first_name']
        if 'last_name' in kwargs:
            user.last_name = kwargs['last_name']
        
        user.save()
        logger.info(f"User {user.email} updated their profile.")
        return UpdateProfileMutation(user=user, errors=None)


class ChangePasswordMutation(graphene.Mutation):
    """
    Changes the password for the currently authenticated user.
    """
    class Arguments:
        old_password = graphene.String(required=True)
        new_password = graphene.String(required=True)
        new_password_confirm = graphene.String(required=True)

    success = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @staticmethod
    def mutate(root, info, old_password, new_password, new_password_confirm):
        user = info.context.user
        if not user.is_authenticated:
            return ChangePasswordMutation(success=False, errors=["Authentication required."])

        if not user.check_password(old_password):
            return ChangePasswordMutation(success=False, errors=["Invalid old password."])

        if new_password != new_password_confirm:
            return ChangePasswordMutation(success=False, errors=["New passwords do not match."])

        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return ChangePasswordMutation(success=False, errors=list(e.messages))

        user.set_password(new_password)
        user.save()

        # Invalidate all existing refresh tokens for the user
        RefreshToken.objects.filter(user=user).update(is_revoked=True)
        
        # Important to maintain the user's session
        update_session_auth_hash(info.context, user)
        
        logger.info(f"User {user.email} changed their password successfully.")
        return ChangePasswordMutation(success=True, errors=None)

class RequestPasswordResetMutation(graphene.Mutation):
    """
    Initiates the password reset process for a user.
    """
    class Arguments:
        email = graphene.String(required=True)
        reset_url_base = graphene.String(required=True, description="The base URL for the password reset form on your frontend, e.g., 'https://my-app.com/reset-password'. The token will be appended as a query parameter.")

    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, email, reset_url_base):
        message = "If an account with that email exists, a password reset link has been sent."
        try:
            user = User.objects.get(email=email)
            
            token = secrets.token_urlsafe(32)
            user.password_reset_token = token
            user.password_reset_token_expires = timezone.now() + timedelta(hours=1)
            user.save()
            
            reset_url = f"{reset_url_base}?token={token}"
            
            send_templated_email(
                recipient=user.email,
                template_id="password-reset", # This ID must exist in the email-service
                context={
                    "name": user.get_full_name(),
                    "reset_url": reset_url,
                }
            )
            
            logger.info(f"Password reset initiated for {email}.")
            
        except User.DoesNotExist:
            logger.warning(f"Password reset requested for non-existent user: {email}")

        return RequestPasswordResetMutation(success=True, message=message)

class ResetPasswordMutation(graphene.Mutation):
    """
    Resets the user's password using a valid token.
    """
    class Arguments:
        token = graphene.String(required=True)
        new_password = graphene.String(required=True)
        new_password_confirm = graphene.String(required=True)

    success = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @staticmethod
    def mutate(root, info, token, new_password, new_password_confirm):
        if new_password != new_password_confirm:
            return ResetPasswordMutation(success=False, errors=["Passwords do not match."])

        try:
            validate_password(new_password)
        except ValidationError as e:
            return ResetPasswordMutation(success=False, errors=list(e.messages))

        try:
            user = User.objects.get(
                password_reset_token=token,
                password_reset_token_expires__gt=timezone.now()
            )
            
            user.set_password(new_password)
            user.password_reset_token = None
            user.password_reset_token_expires = None
            user.save()
            
            logger.info(f"Password reset successfully for user {user.email}.")
            return ResetPasswordMutation(success=True, errors=None)
            
        except User.DoesNotExist:
            logger.warning(f"Invalid or expired password reset token used: {token}")
            return ResetPasswordMutation(success=False, errors=["Invalid or expired token."])
