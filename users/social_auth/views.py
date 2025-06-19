from django.shortcuts import redirect, render
from django.views import View
from django.urls import reverse
import requests
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
import logging
from django.utils import timezone
from datetime import timedelta

from users.models import User
from .utils import StateManager, PKCEManager
from .models import SocialAccount, AuthenticationAttempt

# Configure logging
logger = logging.getLogger(__name__)

class SocialLoginInitiateView(View):
    """
    Handles the initiation of the social login flow.
    Redirects the user to the provider's authentication page.
    """
    def get(self, request, provider):
        if provider == 'google':
            # 1. Generate state and PKCE parameters
            state = StateManager.generate_state()
            code_verifier = PKCEManager.generate_code_verifier()
            code_challenge = PKCEManager.generate_code_challenge(code_verifier)

            # 2. Store them in the session
            request.session['oauth_state'] = state
            request.session['oauth_pkce_verifier'] = code_verifier
            request.session.save()

            # 3. Build the authorization URL
            auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
            client_id = settings.GOOGLE_CLIENT_ID
            redirect_uri = request.build_absolute_uri(reverse('social_auth:callback', args=[provider]))
            
            params = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': 'code',
                'scope': 'openid profile email',
                'state': state,
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
                'access_type': 'offline',
                'prompt': 'select_account',
            }
            
            full_auth_url = f"{auth_url}?{requests.compat.urlencode(params)}"
            logger.info(f"Redirecting user to Google for authentication.")
            return redirect(full_auth_url)
            
        else:
            logger.error(f"Provider '{provider}' not supported.")
            return redirect('/?error=provider-not-supported')

class SocialLoginCallbackView(View):
    """
    Handles the callback from the social login provider.
    Exchanges the authorization code for an access token and retrieves user info.
    """
    def get(self, request, provider):
        if provider == 'google':
            
            # --- Security Verification ---
            received_state = request.GET.get('state')
            session_state = request.session.get('oauth_state')

            if not StateManager.validate_state(session_state, received_state):
                logger.warning("Social login state validation failed.")
                return redirect('/?error=state-mismatch')
            
            code_verifier = request.session.get('oauth_pkce_verifier')
            if not code_verifier:
                logger.warning("Social login code verifier not found in session.")
                return redirect('/?error=pkce-error')

            # --- Token Exchange ---
            code = request.GET.get('code')
            if not code:
                logger.warning("No authorization code provided in callback.")
                return redirect('/?error=no-code')

            token_url = "https://oauth2.googleapis.com/token"
            redirect_uri = request.build_absolute_uri(reverse('social_auth:callback', args=[provider]))
            
            token_payload = {
                'client_id': settings.GOOGLE_CLIENT_ID,
                'client_secret': settings.GOOGLE_OAUTH_CLIENT_SECRET,
                'code': code,
                'code_verifier': code_verifier,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri,
            }

            try:
                token_response = requests.post(token_url, data=token_payload)
                token_response.raise_for_status()
                token_data = token_response.json()
            except requests.RequestException as e:
                logger.error(f"Failed to exchange authorization code for token: {e}")
                return redirect('/?error=token-exchange-failed')

            # --- Fetch User Info ---
            userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
            headers = {'Authorization': f'Bearer {token_data["access_token"]}'}
            
            try:
                userinfo_response = requests.get(userinfo_url, headers=headers)
                userinfo_response.raise_for_status()
                user_info = userinfo_response.json()
            except requests.RequestException as e:
                logger.error(f"Failed to fetch user info from provider: {e}")
                return redirect('/?error=userinfo-fetch-failed')

            # --- User and Social Account Sync ---
            user = self.sync_user_and_social_account(provider, user_info, token_data)

            # --- Generate App Tokens ---
            tokens = get_tokens_for_user(user)

            # --- Cleanup and Redirect ---
            request.session.pop('oauth_state', None)
            request.session.pop('oauth_pkce_verifier', None)
            
            # TODO: Redirect to a more robust frontend URL handler
            return render(request, 'auth/callback.html', {'tokens': tokens})
            
        else:
            logger.error(f"Callback from unsupported provider '{provider}'.")
            return redirect('/?error=provider-not-supported')

    def sync_user_and_social_account(self, provider, user_info, token_data):
        """
        Finds or creates a user and a corresponding social account.
        """
        provider_id = user_info.get('sub')
        email = user_info.get('email')

        # Step 1: Find or create the User based on email.
        user, user_created = User.objects.get_or_create(
            email=email,
            defaults={
                'first_name': user_info.get('given_name', ''),
                'last_name': user_info.get('family_name', ''),
                'is_active': True,
            }
        )
        if user_created:
            user.set_unusable_password()
            user.save()

        # Step 2: Now, get or create the SocialAccount and link it to the user.
        social_account, created = SocialAccount.objects.get_or_create(
            provider=provider,
            provider_id=provider_id,
            defaults={
                'user': user,
                'email': email,
                'extra_data': user_info,
            }
        )
        
        # This handles an edge case where a social account might exist but not be linked.
        if not created and social_account.user != user:
            social_account.user = user

        # Update tokens and other data
        social_account.access_token = token_data.get('access_token')
        social_account.refresh_token = token_data.get('refresh_token')
        
        expires_in = token_data.get('expires_in')
        if expires_in:
            social_account.token_expires_at = timezone.now() + timedelta(seconds=expires_in)
            
        social_account.save()

        return user

def get_tokens_for_user(user):
    """
    Generates JWT tokens for a given user.
    """
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    } 