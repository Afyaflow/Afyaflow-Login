from datetime import datetime, timedelta
from typing import Optional, Tuple

from django.conf import settings
from django.utils import timezone
from jose import jwt, JWTError
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from users.models import User, RegisteredClient
from users.client_jwt import ClientJWTAuthenticationBackend


class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request) -> Optional[Tuple[User, dict]]:
        # Get the Authorization header
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return None

        try:
            # Check if it's a Bearer token
            auth_type, token = auth_header.split()
            if auth_type.lower() != 'bearer':
                return None

            # Try client-specific authentication first if client is available
            if hasattr(request, 'client') and request.client:
                auth_result = ClientJWTAuthenticationBackend.authenticate_token(token, request.client)
                if auth_result:
                    return auth_result['user'], auth_result['payload']
                else:
                    raise AuthenticationFailed('Invalid or expired token')

            # Fallback to legacy JWT authentication
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )

            # Check if token is blacklisted
            token_jti = payload.get('jti')
            if token_jti:
                from .models import BlacklistedToken
                if BlacklistedToken.objects.filter(token_jti=token_jti).exists():
                    raise AuthenticationFailed('Token has been revoked')

            # Get user from payload
            user_id = payload.get('sub')
            if user_id is None:
                raise AuthenticationFailed('Invalid token payload')

            # Get the user
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise AuthenticationFailed('User not found')

            # Check if user is active and not suspended
            if not user.is_active:
                raise AuthenticationFailed('User is inactive')
            if user.is_suspended:
                raise AuthenticationFailed('User account is suspended')

            return user, payload

        except JWTError:
            raise AuthenticationFailed('Invalid token')
        except ValueError:
            raise AuthenticationFailed('Invalid authorization header')

    def authenticate_mfa_token(self, token: str) -> Tuple[User, dict]:
        """
        Authenticates a user from a raw MFA token string, bypassing the request header.
        This is specifically for the second step of the MFA login flow.
        """
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )

            user_id = payload.get('sub')
            if user_id is None:
                raise AuthenticationFailed('Invalid MFA token payload.')

            user = User.objects.get(id=user_id)
            if not user.is_active or user.is_suspended:
                raise AuthenticationFailed('User account is inactive or suspended.')

            return user, payload

        except JWTError:
            raise AuthenticationFailed('Invalid or expired MFA token.')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found.')


def create_token(user_id: str, token_type: str = 'access') -> Tuple[str, datetime]:
    """
    Create a new JWT token for the given user
    """
    now = timezone.now()
    
    # Set token lifetime based on type
    if token_type == 'access':
        lifetime = timedelta(minutes=settings.JWT_ACCESS_TOKEN_LIFETIME)
    elif token_type == 'mfa':
        lifetime = timedelta(minutes=settings.JWT_MFA_TOKEN_LIFETIME)
    else:  # refresh token
        lifetime = timedelta(minutes=settings.JWT_REFRESH_TOKEN_LIFETIME)
    
    expires_at = now + lifetime
    
    # Generate unique token ID for blacklisting capability
    import uuid
    token_jti = str(uuid.uuid4())

    # Create the token payload
    payload = {
        'sub': str(user_id),  # subject (user id)
        'type': token_type,
        'iat': now.timestamp(),  # issued at
        'exp': expires_at.timestamp(),  # expiration time
        'jti': token_jti,  # JWT ID for blacklisting
    }
    
    # Create the token
    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    
    return token, expires_at


def create_oct_token(user_id: str, organization_id: str, user_email: str = None,
                    user_first_name: str = None, user_last_name: str = None,
                    user_roles: list = None) -> Tuple[str, datetime]:
    """
    Create a new Organization Context Token (OCT) for the given user and organization.
    Enhanced version that includes user details in the token payload.
    """
    now = timezone.now()
    lifetime = timedelta(minutes=settings.JWT_OCT_LIFETIME)
    expires_at = now + lifetime

    # Create the base token payload
    payload = {
        'sub': str(user_id),  # subject (user id)
        'org_id': str(organization_id), # organization id
        'type': 'oct',
        'iat': now.timestamp(),  # issued at
        'exp': expires_at.timestamp(),  # expiration time
    }

    # Add enhanced user details if provided
    if user_email:
        payload['user_email'] = user_email
    if user_first_name:
        payload['user_first_name'] = user_first_name
    if user_last_name:
        payload['user_last_name'] = user_last_name
    if user_roles:
        payload['user_roles'] = user_roles

    # Create the token
    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    return token, expires_at


def blacklist_user_tokens(user, reason="Security event"):
    """
    Blacklist all active JWT tokens for a user.
    This is used when password changes, account suspension, etc.
    """
    from .models import BlacklistedToken, RefreshToken
    import logging

    logger = logging.getLogger(__name__)

    # Get all active refresh tokens for the user
    refresh_tokens = RefreshToken.objects.filter(
        user=user,
        is_revoked=False,
        expires_at__gt=timezone.now()
    )

    # Extract JTI from refresh tokens and blacklist them
    for refresh_token in refresh_tokens:
        try:
            # Decode without verification to get JTI
            payload = jwt.get_unverified_claims(refresh_token.token)
            token_jti = payload.get('jti')

            if token_jti:
                BlacklistedToken.objects.get_or_create(
                    token_jti=token_jti,
                    defaults={
                        'user': user,
                        'reason': reason,
                        'expires_at': refresh_token.expires_at
                    }
                )
        except Exception as e:
            logger.warning(f"Failed to blacklist token for user {user.email}: {e}")

    # Revoke all refresh tokens
    refresh_tokens.update(is_revoked=True)

    logger.info(f"Blacklisted all tokens for user {user.email}. Reason: {reason}")