from datetime import datetime, timedelta
from typing import Optional, Tuple

from django.conf import settings
from django.utils import timezone
from jose import jwt, JWTError
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from users.models import User


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

            # Decode and validate the token
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )

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
    
    # Create the token payload
    payload = {
        'sub': str(user_id),  # subject (user id)
        'type': token_type,
        'iat': now.timestamp(),  # issued at
        'exp': expires_at.timestamp(),  # expiration time
    }
    
    # Create the token
    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    
    return token, expires_at


def create_oct_token(user_id: str, organization_id: str) -> Tuple[str, datetime]:
    """
    Create a new Organization Context Token (OCT) for the given user and organization.
    """
    now = timezone.now()
    lifetime = timedelta(minutes=settings.JWT_OCT_LIFETIME)
    expires_at = now + lifetime

    # Create the token payload
    payload = {
        'sub': str(user_id),  # subject (user id)
        'org_id': str(organization_id), # organization id
        'type': 'oct',
        'iat': now.timestamp(),  # issued at
        'exp': expires_at.timestamp(),  # expiration time
    }

    # Create the token
    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    return token, expires_at 