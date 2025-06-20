import graphene
from graphql_jwt.shortcuts import create_refresh_token, get_token

from social_auth.services import (
    exchange_code_for_token,
    get_google_user_info,
    sync_user_and_social_account,
)
from users.graphql.types import UserType
from social_auth.models import AuthenticationAttempt
from social_auth.security import StateManager


class LoginWithGoogle(graphene.Mutation):
    """
    Mutation to log in a user with a Google authorization code.
    """

    class Arguments:
        authorization_code = graphene.String(required=True)
        state = graphene.String(required=True)

    access_token = graphene.String()
    refresh_token = graphene.String()
    user = graphene.Field(UserType)

    @staticmethod
    def mutate(root, info, authorization_code, state):
        validated_state = StateManager.validate_state(state)
        if not validated_state:
            raise Exception("Invalid or expired state token.")

        try:
            auth_attempt = AuthenticationAttempt.objects.get(state=validated_state)
            redirect_uri = auth_attempt.redirect_uri
        except AuthenticationAttempt.DoesNotExist:
            raise Exception("Authentication attempt not found for the given state.")

        token_data = exchange_code_for_token(authorization_code, redirect_uri)
        if not token_data or "access_token" not in token_data:
            raise Exception(
                "Google authentication failed. Could not exchange code for token."
            )

        google_access_token = token_data["access_token"]
        user_info = get_google_user_info(google_access_token)
        if not user_info:
            raise Exception(
                "Google authentication failed. Could not retrieve user info."
            )

        user, _ = sync_user_and_social_account(
            provider="google",
            provider_user_id=user_info["sub"],
            email=user_info["email"],
            first_name=user_info.get("given_name"),
            last_name=user_info.get("family_name"),
            extra_data=user_info,
        )

        access_token = get_token(user)
        refresh_token = create_refresh_token(user)

        # Clean up the authentication attempt
        auth_attempt.delete()

        return LoginWithGoogle(
            access_token=access_token,
            refresh_token=str(refresh_token),
            user=user,
        ) 