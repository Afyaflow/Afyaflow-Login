import logging
import requests
from django.conf import settings
from django.utils import timezone
from ..models import User, RefreshToken
from ..authentication import create_token

# Initialize logger
logger = logging.getLogger(__name__)

def create_auth_payload(user):
    """
    Creates JWTs and saves the refresh token.
    """
    access_token_str, _ = create_token(user.id, token_type='access')
    refresh_token_str, refresh_expires_at = create_token(user.id, token_type='refresh')

    RefreshToken.objects.create(
        user=user,
        token=refresh_token_str,
        expires_at=refresh_expires_at
    )
    
    # Update last_login
    user.last_login = timezone.now()
    user.save(update_fields=['last_login'])

    logger.info(f"Successfully created tokens for user {user.email}")

    return {
        "user": user,
        "access_token": access_token_str,
        "refresh_token": refresh_token_str,
    }

class GoogleAuthService:
    """
    Service to handle Google OAuth2 authentication.
    """
    TOKEN_INFO_URL = 'https://oauth2.googleapis.com/tokeninfo'

    def __init__(self, id_token):
        self.id_token = id_token
        self.client_id = getattr(settings, 'GOOGLE_CLIENT_ID', None)

    def validate_token(self):
        """
        Validates the Google ID token and returns the token info.
        """
        if not self.client_id:
            logger.error("GoogleAuthService: GOOGLE_CLIENT_ID setting is not configured.")
            raise ValueError("Server configuration error: Google Client ID not set.")

        try:
            response = requests.get(f'{self.TOKEN_INFO_URL}?id_token={self.id_token}')
            response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
            token_info = response.json()
            
            # Verify audience
            if token_info.get('aud') != self.client_id:
                raise ValueError("ID token audience mismatch.")
            
            # Verify issuer
            issuer = token_info.get('iss')
            if issuer not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError("Invalid ID token issuer.")

            if not token_info.get('email_verified', False):
                raise ValueError("Email not verified with Google.")

            return token_info

        except requests.RequestException as e:
            logger.error(f"GoogleAuthService: Error validating Google ID token: {e}")
            raise ValueError("Error validating Google ID token.")
        except Exception as e:
            logger.error(f"GoogleAuthService: Unexpected error during token validation: {e}")
            raise ValueError(f"An unexpected error occurred: {str(e)}")

    @staticmethod
    def get_or_create_user(token_info):
        """
        Gets an existing user or creates a new one based on the token info.
        Links the social account.
        """
        google_user_id = token_info.get('sub')
        email = token_info.get('email')

        if not google_user_id or not email:
            raise ValueError("Required user information (sub, email) not in token.")

        from allauth.socialaccount.models import SocialAccount

        try:
            # Find user by social account
            social_account = SocialAccount.objects.get(provider='google', uid=google_user_id)
            user = social_account.user
            logger.info(f"Found existing social account for user {user.email}")
            social_account.extra_data = token_info
            social_account.save()
            return user
        except SocialAccount.DoesNotExist:
            try:
                # Find user by email and link account
                user = User.objects.get(email=email)
                logger.info(f"Found existing user with email {email}, linking social account.")
            except User.DoesNotExist:
                # Create a new user
                logger.info(f"Creating new user for email {email}")
                given_name = token_info.get('given_name', '')
                family_name = token_info.get('family_name', '')
                if not given_name and not family_name and token_info.get('name'):
                    parts = token_info.get('name').split(' ', 1)
                    given_name = parts[0]
                    family_name = parts[1] if len(parts) > 1 else ''

                user = User(
                    email=email,
                    first_name=given_name,
                    last_name=family_name,
                    is_active=True
                )
                user.set_unusable_password()
                user.save()
            
            # Create the social account link
            SocialAccount.objects.create(
                user=user,
                provider='google',
                uid=google_user_id,
                extra_data=token_info
            )
            return user
