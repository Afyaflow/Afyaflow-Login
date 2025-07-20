import functools
import logging
import graphene
from graphql import GraphQLError
from django.utils import timezone

from ..models import RegisteredClient
from ..client_utils import ClientCredentialManager
from ..client_security import ClientSecurityManager

logger = logging.getLogger(__name__)


def require_client_auth(allowed_client_types=None):
    """
    Decorator to require client authentication for GraphQL mutations.
    
    Args:
        allowed_client_types (list, optional): List of allowed client types.
                                             If None, all client types are allowed.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(cls, root, info, *args, **kwargs):
            # Extract client credentials from arguments
            client_id = kwargs.get('client_id') or kwargs.get('clientId')
            api_key = kwargs.get('client_api_key') or kwargs.get('clientApiKey')
            
            if not client_id or not api_key:
                raise GraphQLError(
                    "Client authentication required. Please provide clientId and clientApiKey.",
                    extensions={"code": "CLIENT_AUTH_REQUIRED"}
                )
            
            # Validate client credentials
            try:
                client = RegisteredClient.objects.get(client_id=client_id, is_active=True)
            except RegisteredClient.DoesNotExist:
                logger.warning(f"Invalid client ID attempted: {client_id}")
                raise GraphQLError(
                    "Invalid client credentials.",
                    extensions={"code": "INVALID_CLIENT"}
                )
            
            # Verify API key
            if not ClientCredentialManager.validate_client_credentials(
                client_id, api_key, client.api_key_hash
            ):
                logger.warning(f"Invalid API key for client: {client_id}")
                raise GraphQLError(
                    "Invalid client credentials.",
                    extensions={"code": "INVALID_CLIENT"}
                )
            
            # Check if client type is allowed
            if allowed_client_types and client.client_type not in allowed_client_types:
                logger.warning(f"Client type {client.client_type} not allowed for this operation")
                raise GraphQLError(
                    f"Client type {client.client_type} is not authorized for this operation.",
                    extensions={"code": "CLIENT_TYPE_NOT_ALLOWED"}
                )
            
            # Validate client security policies
            request_data = {
                'is_secure': info.context.is_secure(),
                'origin': info.context.META.get('HTTP_ORIGIN'),
                'device_fingerprint': info.context.META.get('HTTP_X_DEVICE_FINGERPRINT'),
            }
            
            validation_result = ClientSecurityManager.validate_client_request(client, request_data)
            if not validation_result['valid']:
                logger.warning(f"Security policy violation for client {client_id}: {validation_result['violations']}")
                raise GraphQLError(
                    f"Security policy violation: {'; '.join(validation_result['violations'])}",
                    extensions={"code": "SECURITY_POLICY_VIOLATION"}
                )
            
            # Store client information in context for use in the mutation
            info.context.client = client
            info.context.client_type = client.client_type
            
            # Remove client credentials from kwargs to avoid passing them to the mutation
            kwargs.pop('client_id', None)
            kwargs.pop('clientId', None)
            kwargs.pop('client_api_key', None)
            kwargs.pop('clientApiKey', None)
            
            # Log successful client authentication
            logger.info(f"Client authentication successful for {client.client_name} ({client.client_type})")
            
            return func(cls, root, info, *args, **kwargs)
        
        return wrapper
    return decorator


def get_client_from_context(info):
    """
    Get the authenticated client from the GraphQL context.
    
    Args:
        info: GraphQL resolve info object
        
    Returns:
        RegisteredClient: The authenticated client or None
    """
    return getattr(info.context, 'client', None)


def get_client_type_from_context(info):
    """
    Get the authenticated client type from the GraphQL context.
    
    Args:
        info: GraphQL resolve info object
        
    Returns:
        str: The client type or None
    """
    return getattr(info.context, 'client_type', None)


def require_patient_client(func):
    """
    Decorator to require patient client types (PATIENT_WEB, PATIENT_MOBILE).
    """
    return require_client_auth(['PATIENT_WEB', 'PATIENT_MOBILE'])(func)


def require_provider_client(func):
    """
    Decorator to require provider client types (PROVIDER_WEB, PROVIDER_MOBILE).
    """
    return require_client_auth(['PROVIDER_WEB', 'PROVIDER_MOBILE'])(func)


def require_admin_client(func):
    """
    Decorator to require admin client type (ADMIN_WEB).
    """
    return require_client_auth(['ADMIN_WEB'])(func)


class ClientAuthMixin:
    """
    Mixin class to add client authentication support to GraphQL mutations.
    """
    
    @classmethod
    def add_client_auth_arguments(cls, arguments_class):
        """
        Add client authentication arguments to a GraphQL mutation.
        
        Args:
            arguments_class: The Arguments class to extend
        """
        # Add client authentication fields
        arguments_class.client_id = graphene.String(
            required=True,
            description="Client ID for authentication"
        )
        arguments_class.client_api_key = graphene.String(
            required=True,
            description="Client API key for authentication"
        )
        
        return arguments_class
    
    @classmethod
    def validate_client_auth(cls, info, client_id, client_api_key, allowed_client_types=None):
        """
        Validate client authentication for a mutation.
        
        Args:
            info: GraphQL resolve info
            client_id: Client ID
            client_api_key: Client API key
            allowed_client_types: List of allowed client types
            
        Returns:
            RegisteredClient: The validated client
            
        Raises:
            GraphQLError: If authentication fails
        """
        if not client_id or not client_api_key:
            raise GraphQLError(
                "Client authentication required.",
                extensions={"code": "CLIENT_AUTH_REQUIRED"}
            )
        
        try:
            client = RegisteredClient.objects.get(client_id=client_id, is_active=True)
        except RegisteredClient.DoesNotExist:
            raise GraphQLError(
                "Invalid client credentials.",
                extensions={"code": "INVALID_CLIENT"}
            )
        
        if not ClientCredentialManager.validate_client_credentials(
            client_id, client_api_key, client.api_key_hash
        ):
            raise GraphQLError(
                "Invalid client credentials.",
                extensions={"code": "INVALID_CLIENT"}
            )
        
        if allowed_client_types and client.client_type not in allowed_client_types:
            raise GraphQLError(
                f"Client type {client.client_type} is not authorized for this operation.",
                extensions={"code": "CLIENT_TYPE_NOT_ALLOWED"}
            )
        
        # Store in context
        info.context.client = client
        info.context.client_type = client.client_type
        
        return client


def log_client_operation(operation_type, client, user=None, success=True, details=None):
    """
    Log client operations for audit purposes.
    
    Args:
        operation_type (str): Type of operation (login, register, etc.)
        client (RegisteredClient): The client performing the operation
        user (User, optional): The user involved in the operation
        success (bool): Whether the operation was successful
        details (dict, optional): Additional operation details
    """
    try:
        from ..models import AuthenticationAttempt
        
        AuthenticationAttempt.objects.create(
            email=user.email if user else None,
            attempt_type=operation_type,
            ip_address='127.0.0.1',  # This should be extracted from request
            user_agent='GraphQL Client',  # This should be extracted from request
            success=success,
            user=user,
            client=client,
            client_type=client.client_type,
            security_context={
                'operation_type': operation_type,
                'client_name': client.client_name,
                'timestamp': timezone.now().isoformat(),
                'details': details or {}
            }
        )
        
        logger.info(f"Logged {operation_type} operation for client {client.client_name}")
        
    except Exception as e:
        logger.error(f"Failed to log client operation: {e}")


def get_client_token_config(client, user=None):
    """
    Get token configuration for a client and user combination.
    
    Args:
        client (RegisteredClient): The client
        user (User, optional): The user
        
    Returns:
        dict: Token configuration
    """
    return ClientSecurityManager.get_token_config_for_client(client, user)
