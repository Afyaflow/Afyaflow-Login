from datetime import datetime, timedelta
from typing import Optional, Tuple

from django.conf import settings
from django.utils import timezone
from jose import jwt, JWTError
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from users.models import User


def get_jwt_secret_for_user_type(user_type: str) -> str:
    """
    Get the appropriate JWT secret based on user type for gateway compliance.

    Args:
        user_type: The user type ('provider', 'patient', 'operations')

    Returns:
        The appropriate JWT secret for the user type

    Raises:
        ValueError: If user_type is invalid
    """
    secret_mapping = {
        'provider': settings.PROVIDER_AUTH_TOKEN_SECRET,
        'patient': settings.PATIENT_AUTH_TOKEN_SECRET,
        'operations': settings.OPERATIONS_AUTH_TOKEN_SECRET,
    }

    if user_type not in secret_mapping:
        raise ValueError(f"Invalid user_type: {user_type}. Must be one of: {list(secret_mapping.keys())}")

    return secret_mapping[user_type]


def get_oct_secret() -> str:
    """Get the Organization Context Token secret."""
    return settings.ORG_CONTEXT_TOKEN_SECRET


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

            # Decode and validate the token with appropriate secret (gateway compliance)
            payload = self._decode_token_with_appropriate_secret(token)

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

            # Verify user_type in token matches user's actual type (gateway compliance)
            token_user_type = payload.get('user_type')
            if token_user_type and token_user_type != user.user_type:
                raise AuthenticationFailed('Token user type mismatch')

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

    def _decode_token_with_appropriate_secret(self, token: str) -> dict:
        """
        Decode JWT token using the appropriate secret based on user type.
        Since we need to decode to get user_type, we try different secrets.
        """
        # List of secrets to try (user-type-specific + OCT + legacy fallback)
        secrets_to_try = [
            ('provider', settings.PROVIDER_AUTH_TOKEN_SECRET),
            ('patient', settings.PATIENT_AUTH_TOKEN_SECRET),
            ('operations', settings.OPERATIONS_AUTH_TOKEN_SECRET),
            ('oct', settings.ORG_CONTEXT_TOKEN_SECRET),  # Organization Context Token
            ('legacy', settings.JWT_SECRET_KEY),  # Fallback for old tokens
        ]

        last_error = None
        for secret_name, secret in secrets_to_try:
            try:
                payload = jwt.decode(
                    token,
                    secret,
                    algorithms=[settings.JWT_ALGORITHM]
                )

                # If we successfully decoded, verify the token type matches the secret used
                token_type = payload.get('type', payload.get('user_type'))

                if token_type and secret_name != 'legacy':
                    # For OCT tokens, check if type is 'oct'
                    if secret_name == 'oct' and token_type == 'oct':
                        return payload
                    # For user-type tokens, check if user_type matches
                    elif secret_name != 'oct' and token_type == secret_name:
                        return payload
                    # Wrong secret for this token type
                    else:
                        continue

                return payload

            except JWTError as e:
                last_error = e
                continue

        # If we get here, none of the secrets worked
        raise last_error or JWTError("Unable to decode token with any available secret")

    def authenticate_token(self, token: str) -> Tuple[User, dict]:
        """
        Authenticate a user from a raw token string.
        This is used by the token introspection endpoint for service-to-service authentication.

        Returns:
            Tuple[User, dict]: User object and token payload

        Raises:
            AuthenticationFailed: If token is invalid or user not found
        """
        try:
            # Decode and validate the token with appropriate secret
            payload = self._decode_token_with_appropriate_secret(token)

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

            # Verify user_type in token matches user's actual type
            token_user_type = payload.get('user_type')
            if token_user_type and token_user_type != user.user_type:
                raise AuthenticationFailed('Token user type mismatch')

            # Check if user is active and not suspended
            if not user.is_active:
                raise AuthenticationFailed('User is inactive')
            if user.is_suspended:
                raise AuthenticationFailed('User account is suspended')

            return user, payload

        except JWTError as e:
            raise AuthenticationFailed(f'Invalid token: {str(e)}')

    def authenticate_mfa_token(self, token: str) -> Tuple[User, dict]:
        """
        Authenticates a user from a raw MFA token string, bypassing the request header.
        This is specifically for the second step of the MFA login flow.
        """
        try:
            # Use the same multi-secret decoding logic for MFA tokens
            payload = self._decode_token_with_appropriate_secret(token)

            user_id = payload.get('sub')
            if user_id is None:
                raise AuthenticationFailed('Invalid MFA token payload.')

            user = User.objects.get(id=user_id)

            # Verify user_type in token matches user's actual type
            token_user_type = payload.get('user_type')
            if token_user_type and token_user_type != user.user_type:
                raise AuthenticationFailed('Token user type mismatch')

            if not user.is_active or user.is_suspended:
                raise AuthenticationFailed('User account is inactive or suspended.')

            return user, payload

        except JWTError:
            raise AuthenticationFailed('Invalid or expired MFA token.')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found.')


def create_token(user_id: str, token_type: str = 'access', user_type: str = None,
                current_context: str = None) -> Tuple[str, datetime]:
    """
    Create a new JWT token for the given user with gateway compliance.

    Args:
        user_id: The user's ID
        token_type: Type of token ('access', 'refresh', 'mfa')
        user_type: User type for gateway compliance ('provider', 'patient', 'operations')
        current_context: Current role context ('patient', 'provider') for dual-role users

    Returns:
        Tuple of (token_string, expires_at_datetime)
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

    # Create the token payload with user_type for gateway compliance
    payload = {
        'sub': str(user_id),  # subject (user id)
        'user_type': user_type,  # Gateway compliance: user type
        'type': token_type,
        'iat': now.timestamp(),  # issued at
        'exp': expires_at.timestamp(),  # expiration time
        'jti': token_jti,  # JWT ID for blacklisting
    }

    # Add context information for dual-role users
    if current_context and current_context != user_type:
        payload['current_context'] = current_context
        payload['original_user_type'] = user_type

    # Get the appropriate secret for the user type
    jwt_secret = get_jwt_secret_for_user_type(user_type)

    # Create the token
    token = jwt.encode(
        payload,
        jwt_secret,
        algorithm=settings.JWT_ALGORITHM
    )

    return token, expires_at


def create_oct_token(user_id: str, organization_id: str, user_email: str = None,
                    user_first_name: str = None, user_last_name: str = None,
                    user_roles: list = None, branch_id: str = None,
                    cluster_id: str = None, subscribed_services: list = None) -> Tuple[str, datetime]:
    """
    Create a new Organization Context Token (OCT) for the given user and organization.
    Enhanced version with gateway compliance and organization context.

    Args:
        user_id: The user's ID
        organization_id: The organization ID
        user_email: User's email address
        user_first_name: User's first name
        user_last_name: User's last name
        user_roles: List of user roles within the organization
        branch_id: Organization branch ID (gateway compliance)
        cluster_id: Organization cluster ID (gateway compliance)
        subscribed_services: List of services the organization subscribes to

    Returns:
        Tuple of (oct_token_string, expires_at_datetime)
    """
    now = timezone.now()
    lifetime = timedelta(minutes=settings.JWT_OCT_LIFETIME)
    expires_at = now + lifetime

    # Create the base token payload with gateway compliance fields
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

    # Add gateway compliance organization context
    if branch_id:
        payload['branchId'] = str(branch_id)
    if cluster_id:
        payload['clusterId'] = str(cluster_id)
    if subscribed_services:
        payload['subscribedServices'] = subscribed_services

    # Create the token using separate OCT secret for gateway compliance
    token = jwt.encode(
        payload,
        get_oct_secret(),
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