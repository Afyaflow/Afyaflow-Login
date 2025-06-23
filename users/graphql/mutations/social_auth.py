import graphene
from django.conf import settings
from django.contrib.auth import login
from django.db import transaction
from django.contrib.sites.shortcuts import get_current_site
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.microsoft.views import MicrosoftGraphOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.helpers import complete_social_login
from allauth.socialaccount.models import SocialLogin, SocialToken, SocialApp
import requests
import logging

from ..types import AuthPayloadType
from ..services import create_auth_payload

logger = logging.getLogger(__name__)

class OAuth2Response:
    """Mock response object for OAuth2 providers"""
    def __init__(self, response):
        self.status_code = response.status_code
        self._json = response.json()
        self.text = response.text

    def json(self):
        return self._json

    def get(self, key, default=None):
        return self._json.get(key, default)

class BaseSocialAuthMutation(graphene.Mutation):
    """Base class for social authentication mutations."""
    class Arguments:
        access_token = graphene.String(required=True)
        id_token = graphene.String(required=False)

    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, **kwargs):
        raise NotImplementedError("Subclasses must implement mutate method")

    @classmethod
    def get_social_app(cls, provider, request):
        try:
            site = get_current_site(request)
            return SocialApp.objects.get(provider=provider, sites=site)
        except SocialApp.DoesNotExist:
            raise Exception(f"No social app configured for provider: {provider}")
        except Exception as e:
            logger.error(f"Error getting social app: {str(e)}")
            raise Exception(f"Error getting social app configuration: {str(e)}")

class GoogleLoginMutation(BaseSocialAuthMutation):
    """Handles Google OAuth2 authentication."""
    
    @classmethod
    def mutate(cls, root, info, access_token, id_token=None):
        try:
            adapter = GoogleOAuth2Adapter(info.context)
            app = cls.get_social_app('google', info.context)
            
            # Create token
            token = SocialToken(
                app=app,
                token=access_token,
            )
            if id_token:
                token.token_secret = id_token

            # Fetch user info from Google
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get('https://www.googleapis.com/oauth2/v3/userinfo', headers=headers)
            if response.status_code != 200:
                raise Exception("Failed to get user info from Google")
            
            # Create a response object that the adapter expects
            oauth2_response = OAuth2Response(response)

            # Get user info from Google
            provider = adapter.get_provider()
            user_info = adapter.complete_login(info.context, app, token, response=oauth2_response)
            user_info.token = token

            # Create social login instance
            social_login = SocialLogin(
                user=user_info.user,
                account=user_info.account,
                token=token
            )

            # Complete the social login process
            with transaction.atomic():
                user = social_login.save(info.context)
                
                if not user.is_active:
                    return cls(auth_payload=None, errors=["Your account is not active."])
                
                # Log the user in
                login(info.context, user)
                
                # Create JWT tokens
                auth_data = create_auth_payload(user)
                return cls(auth_payload=AuthPayloadType(**auth_data))

        except Exception as e:
            logger.error(f"Google authentication error: {str(e)}")
            return cls(auth_payload=None, errors=[str(e)])

class MicrosoftLoginMutation(BaseSocialAuthMutation):
    """Handles Microsoft OAuth2 authentication."""
    
    @classmethod
    def mutate(cls, root, info, access_token, id_token=None):
        try:
            adapter = MicrosoftGraphOAuth2Adapter(info.context)
            app = cls.get_social_app('microsoft', info.context)
            
            # Create token
            token = SocialToken(
                app=app,
                token=access_token,
            )
            if id_token:
                token.token_secret = id_token

            # Fetch user info from Microsoft Graph API
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
            if response.status_code != 200:
                raise Exception("Failed to get user info from Microsoft")
            
            # Create a response object that the adapter expects
            oauth2_response = OAuth2Response(response)

            # Get user info from Microsoft
            provider = adapter.get_provider()
            user_info = adapter.complete_login(info.context, app, token, response=oauth2_response)
            user_info.token = token

            # Create social login instance
            social_login = SocialLogin(
                user=user_info.user,
                account=user_info.account,
                token=token
            )

            # Complete the social login process
            with transaction.atomic():
                user = social_login.save(info.context)
                
                if not user.is_active:
                    return cls(auth_payload=None, errors=["Your account is not active."])
                
                # Log the user in
                login(info.context, user)
                
                # Create JWT tokens
                auth_data = create_auth_payload(user)
                return cls(auth_payload=AuthPayloadType(**auth_data))

        except Exception as e:
            logger.error(f"Microsoft authentication error: {str(e)}")
            return cls(auth_payload=None, errors=[str(e)]) 