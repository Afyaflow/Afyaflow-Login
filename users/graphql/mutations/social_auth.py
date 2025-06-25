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
from users.models import User, AuthenticationAttempt
from ...otp_utils import generate_otp, set_user_otp
from ...communication_client import send_templated_email, send_sms
from ...authentication import create_token
from ..mutations.auth import get_client_ip

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

    @classmethod
    def _handle_login_or_mfa(cls, info, user, provider='unknown'):
        """
        Shared logic to handle post-authentication flow.
        Checks if MFA is enabled for the user. If so, initiates the MFA challenge.
        Otherwise, completes the login and returns JWT tokens.

        Args:
            info: GraphQL info object
            user: User object
            provider: Social auth provider name (e.g., 'google', 'microsoft', 'linkedin')
        """
        # Get client information for security tracking
        client_ip = get_client_ip(info.context)
        user_agent = info.context.META.get('HTTP_USER_AGENT', 'Unknown')

        # Import required modules at the beginning
        from ...security_middleware import auth_attempt_tracker
        from ...models import AuthenticationAttempt

        enabled_methods = []
        if user.mfa_totp_setup_complete:
            enabled_methods.append("TOTP")
        if user.mfa_email_enabled:
            enabled_methods.append("EMAIL")
        # Ensure phone is verified before listing SMS as an option
        if user.mfa_sms_enabled and user.phone_number_verified:
            enabled_methods.append("SMS")

        if not enabled_methods:
            # No MFA, record successful attempt and log in directly
            auth_attempt_tracker.record_attempt(client_ip, True, 'social_login', user.email)

            AuthenticationAttempt.objects.create(
                email=user.email,
                attempt_type='social_login',
                ip_address=client_ip,
                user_agent=user_agent,
                success=True,
                user=user,
                provider=provider
            )

            login(info.context, user, backend='allauth.account.auth_backends.AuthenticationBackend')
            auth_data = create_auth_payload(user)
            return cls(auth_payload=AuthPayloadType(**auth_data))

        # MFA is enabled, start the challenge
        logger.info(f"MFA required for user {user.email} during social login.")

        # Record partial success (authentication passed, MFA required)
        AuthenticationAttempt.objects.create(
            email=user.email,
            attempt_type='social_login',
            ip_address=client_ip,
            user_agent=user_agent,
            success=False,  # Not fully successful until MFA completed
            failure_reason='MFA required',
            user=user,
            provider=provider,
            metadata={'mfa_methods': enabled_methods}
        )

        otp = None
        # Send OTPs if Email or SMS MFA are enabled.
        if "EMAIL" in enabled_methods or "SMS" in enabled_methods:
            otp = generate_otp()
            set_user_otp(user, otp, purpose='mfa_login') # Use a specific purpose

            if "EMAIL" in enabled_methods:
                try:
                    send_templated_email(
                        recipient=user.email,
                        template_id='mfa_otp',
                        context={"first_name": user.first_name or "user", "otp_code": otp}
                    )
                except Exception as e:
                    logger.error(f"Failed to send MFA email to {user.email}: {e}")

            if "SMS" in enabled_methods:
                try:
                    message = f"Your AfyaFlow verification code is: {otp}"
                    send_sms(recipient=user.phone_number, message=message)
                except Exception as e:
                    logger.error(f"Failed to send MFA SMS to {user.phone_number}: {e}")
        
        # Create a short-lived MFA token.
        mfa_token, _ = create_token(user.id, token_type='mfa')

        # Return the challenge payload to the client (without access/refresh tokens).
        challenge_payload = AuthPayloadType(
            user=user,
            mfa_required=True,
            mfa_token=mfa_token,
            enabled_mfa_methods=enabled_methods,
        )
        return cls(auth_payload=challenge_payload, errors=None)

class GoogleLoginMutation(BaseSocialAuthMutation):
    """Handles Google OAuth2 authentication."""
    
    @classmethod
    def mutate(cls, root, info, access_token, id_token=None):
        try:
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
                    # If user exists, ensure their email is marked as verified.
                    if not user.email_verified:
                        user.email_verified = True
                        user.save(update_fields=['email_verified'])
                    
                    # Also ensure the allauth EmailAddress model is synced.
                    email_address, created = EmailAddress.objects.get_or_create(user=user, email=user.email)
                    if not email_address.verified:
                        email_address.verified = True
                        email_address.primary = True
                        email_address.save()
                except User.DoesNotExist:
                    # Create new user
                    user = User.objects.create_user(
                        email=email,
                        first_name=user_data.get('given_name', ''),
                        last_name=user_data.get('family_name', ''),
                        is_active=True,
                        email_verified=True  # Set email as verified for social login
                    )
                    user.set_unusable_password()
                    user.save()

                    # Create verified email for allauth
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

                # Get or create social token
                social_token, created = SocialToken.objects.get_or_create(
                    app=app,
                    account=social_account,
                    defaults={
                        'token': access_token,
                        'token_secret': id_token if id_token else ''
                    }
                )

                if not created:
                    # Update existing token
                    social_token.token = access_token
                    social_token.token_secret = id_token if id_token else ''
                    social_token.save()

                # Hand off to the MFA check or final login flow
                return cls._handle_login_or_mfa(info, user, provider='google')

        except Exception as e:
            logger.error(f"Google authentication error: {str(e)}")
            return cls(auth_payload=None, errors=[str(e)])

class MicrosoftLoginMutation(BaseSocialAuthMutation):
    """Handles Microsoft OAuth2 authentication."""
    
    @classmethod
    def mutate(cls, root, info, access_token, id_token=None):
        try:
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
                    # If user exists, ensure their email is marked as verified.
                    if not user.email_verified:
                        user.email_verified = True
                        user.save(update_fields=['email_verified'])
                    
                    # Also ensure the allauth EmailAddress model is synced.
                    email_address, created = EmailAddress.objects.get_or_create(user=user, email=user.email)
                    if not email_address.verified:
                        email_address.verified = True
                        email_address.primary = True
                        email_address.save()
                except User.DoesNotExist:
                    # Create new user
                    user = User.objects.create_user(
                        email=email,
                        first_name=user_data.get('givenName', ''),
                        last_name=user_data.get('surname', ''),
                        is_active=True,
                        email_verified=True  # Set email as verified for social login
                    )
                    user.set_unusable_password()
                    user.save()

                    # Create verified email for allauth
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

                # Get or create social token
                social_token, created = SocialToken.objects.get_or_create(
                    app=app,
                    account=social_account,
                    defaults={
                        'token': access_token,
                        'token_secret': id_token if id_token else ''
                    }
                )

                if not created:
                    # Update existing token
                    social_token.token = access_token
                    social_token.token_secret = id_token if id_token else ''
                    social_token.save()

                # Hand off to the MFA check or final login flow
                return cls._handle_login_or_mfa(info, user, provider='microsoft')

        except Exception as e:
            logger.error(f"Microsoft authentication error: {str(e)}")
            return cls(auth_payload=None, errors=[str(e)])

class LinkedInLoginMutation(BaseSocialAuthMutation):
    """Handles LinkedIn OAuth2 authentication."""
    
    @classmethod
    def mutate(cls, root, info, access_token, id_token=None):
        try:
            app = cls.get_social_app('linkedin_oauth2', info.context)
            
            # 1. Fetch user profile from LinkedIn
            profile_headers = {"Authorization": f"Bearer {access_token}"}
            profile_response = requests.get(
                'https://api.linkedin.com/v2/me?projection=(id,localizedFirstName,localizedLastName)', 
                headers=profile_headers
            )
            if profile_response.status_code != 200:
                raise Exception("Failed to get user profile from LinkedIn")
            
            profile_data = profile_response.json()
            linkedin_user_id = profile_data.get('id')
            if not linkedin_user_id:
                raise Exception("Could not retrieve LinkedIn User ID.")

            # 2. Fetch user email from LinkedIn
            email_headers = {"Authorization": f"Bearer {access_token}"}
            email_response = requests.get(
                'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))',
                headers=email_headers
            )
            if email_response.status_code != 200:
                raise Exception("Failed to get user email from LinkedIn")
            
            email_data = email_response.json()
            email = email_data.get('elements', [{}])[0].get('handle~', {}).get('emailAddress')
            if not email:
                raise Exception("Email not provided by LinkedIn or not accessible.")

            with transaction.atomic():
                try:
                    user = User.objects.get(email=email)
                    if not user.email_verified:
                        user.email_verified = True
                        user.save(update_fields=['email_verified'])
                    
                    email_address, created = EmailAddress.objects.get_or_create(user=user, email=user.email)
                    if not email_address.verified:
                        email_address.verified = True
                        email_address.primary = True
                        email_address.save()
                except User.DoesNotExist:
                    user = User.objects.create_user(
                        email=email,
                        first_name=profile_data.get('localizedFirstName', ''),
                        last_name=profile_data.get('localizedLastName', ''),
                        is_active=True,
                        email_verified=True
                    )
                    user.set_unusable_password()
                    user.save()

                    EmailAddress.objects.create(
                        user=user, email=email, primary=True, verified=True
                    )
                
                # Combine user data for storage in SocialAccount
                user_data = {**profile_data, **email_data}

                social_account, created = SocialAccount.objects.get_or_create(
                    provider='linkedin_oauth2',
                    uid=linkedin_user_id,
                    defaults={'user': user, 'extra_data': user_data}
                )

                if not created:
                    social_account.extra_data = user_data
                    social_account.save()

                social_token, created = SocialToken.objects.get_or_create(
                    app=app,
                    account=social_account,
                    defaults={'token': access_token}
                )

                if not created:
                    social_token.token = access_token
                    social_token.save()

                return cls._handle_login_or_mfa(info, user, provider='linkedin')

        except Exception as e:
            logger.error(f"LinkedIn authentication error: {str(e)}")
            return cls(auth_payload=None, errors=[str(e)]) 