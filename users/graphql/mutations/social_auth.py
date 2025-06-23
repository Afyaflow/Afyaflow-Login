import graphene
from django.conf import settings
from django.contrib.auth import login
from django.db import transaction
from django.contrib.sites.shortcuts import get_current_site
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.microsoft.views import MicrosoftGraphOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.helpers import complete_social_login
from allauth.socialaccount.models import SocialLogin, SocialToken, SocialApp, SocialAccount
from allauth.account.models import EmailAddress
import requests
import logging

from ..types import AuthPayloadType
from ..services import create_auth_payload
from users.models import User

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
            
            # Fetch user info from Google
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get('https://www.googleapis.com/oauth2/v3/userinfo', headers=headers)
            if response.status_code != 200:
                raise Exception("Failed to get user info from Google")
            
            user_data = response.json()
            
            # Get or create user
            email = user_data.get('email')
            if not email:
                raise Exception("Email not provided by Google")

            with transaction.atomic():
                try:
                    # Try to find existing user
                    user = User.objects.get(email=email)
                except User.DoesNotExist:
                    # Create new user
                    user = User.objects.create_user(
                        email=email,
                        first_name=user_data.get('given_name', ''),
                        last_name=user_data.get('family_name', ''),
                        is_active=True
                    )
                    user.set_unusable_password()
                    user.save()

                    # Create verified email
                    EmailAddress.objects.create(
                        user=user,
                        email=email,
                        primary=True,
                        verified=True
                    )

                # Get or create social account
                social_account, created = SocialAccount.objects.get_or_create(
                    provider='google',
                    uid=user_data.get('sub'),
                    defaults={
                        'user': user,
                        'extra_data': user_data
                    }
                )

                if not created:
                    social_account.extra_data = user_data
                    social_account.save()

                # Create social token
                social_token = SocialToken.objects.create(
                    app=app,
                    account=social_account,
                    token=access_token,
                    token_secret=id_token if id_token else ''
                )

                # Log the user in
                login(info.context, user, backend='allauth.account.auth_backends.AuthenticationBackend')
                
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
            
            # Fetch user info from Microsoft Graph API
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
            if response.status_code != 200:
                raise Exception("Failed to get user info from Microsoft")
            
            user_data = response.json()
            
            # Get or create user
            email = user_data.get('mail') or user_data.get('userPrincipalName')
            if not email:
                raise Exception("Email not provided by Microsoft")

            with transaction.atomic():
                try:
                    # Try to find existing user
                    user = User.objects.get(email=email)
                except User.DoesNotExist:
                    # Create new user
                    user = User.objects.create_user(
                        email=email,
                        first_name=user_data.get('givenName', ''),
                        last_name=user_data.get('surname', ''),
                        is_active=True
                    )
                    user.set_unusable_password()
                    user.save()

                    # Create verified email
                    EmailAddress.objects.create(
                        user=user,
                        email=email,
                        primary=True,
                        verified=True
                    )

                # Get or create social account
                social_account, created = SocialAccount.objects.get_or_create(
                    provider='microsoft',
                    uid=user_data.get('id'),
                    defaults={
                        'user': user,
                        'extra_data': user_data
                    }
                )

                if not created:
                    social_account.extra_data = user_data
                    social_account.save()

                # Create social token
                social_token = SocialToken.objects.create(
                    app=app,
                    account=social_account,
                    token=access_token,
                    token_secret=id_token if id_token else ''
                )

                # Log the user in
                login(info.context, user, backend='allauth.account.auth_backends.AuthenticationBackend')
                
                # Create JWT tokens
                auth_data = create_auth_payload(user)
                return cls(auth_payload=AuthPayloadType(**auth_data))

        except Exception as e:
            logger.error(f"Microsoft authentication error: {str(e)}")
            return cls(auth_payload=None, errors=[str(e)]) 