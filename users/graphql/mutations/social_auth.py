import graphene
from django.conf import settings
from django.contrib.auth import login
from django.db import transaction
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.microsoft.views import MicrosoftGraphOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.helpers import complete_social_login
from allauth.socialaccount.models import SocialLogin
import requests
import logging

from ..types import AuthPayloadType
from ..services import create_auth_payload

logger = logging.getLogger(__name__)

class SocialAuthMutation(graphene.Mutation):
    """Base class for social authentication mutations."""
    class Arguments:
        access_token = graphene.String(required=True)
        id_token = graphene.String(required=False)

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    def social_auth_handler(cls, info, access_token, id_token, adapter_class):
        try:
            adapter = adapter_class(info.context)
            provider = adapter.get_provider()
            token_data = {
                'access_token': access_token,
                'id_token': id_token
            }
            
            # Create a social login token
            social_token = adapter.parse_token(token_data)
            social_token.app = provider.app
            
            # Get the user info from the social provider
            user_info = adapter.complete_login(info.context, social_token)
            user_info.token = social_token
            
            # Create a social login instance
            social_login = SocialLogin(user=user_info.user, account=user_info.account, token=social_token)
            
            # Complete the social login process
            with transaction.atomic():
                login_completed = complete_social_login(info.context, social_login)
                if not login_completed.is_active:
                    return cls(auth_payload=None, errors=["Your account is not active."])
                
                # Log the user in
                login(info.context, login_completed)
                
                # Create JWT tokens
                auth_data = create_auth_payload(login_completed)
                return cls(auth_payload=AuthPayloadType(**auth_data))

        except Exception as e:
            logger.error(f"Social authentication error: {str(e)}")
            return cls(auth_payload=None, errors=[str(e)])

class GoogleLoginMutation(SocialAuthMutation):
    """Handles Google OAuth2 authentication."""
    
    @classmethod
    def mutate(cls, root, info, access_token, id_token=None):
        return cls.social_auth_handler(info, access_token, id_token, GoogleOAuth2Adapter)

class MicrosoftLoginMutation(SocialAuthMutation):
    """Handles Microsoft OAuth2 authentication."""
    
    @classmethod
    def mutate(cls, root, info, access_token, id_token=None):
        return cls.social_auth_handler(info, access_token, id_token, MicrosoftGraphOAuth2Adapter) 