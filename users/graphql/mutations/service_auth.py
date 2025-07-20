"""
GraphQL mutations for service authentication and token management.
"""

import graphene
from graphql import GraphQLError
from django.db import transaction

from users.models import ServiceAccount
from users.service_jwt import ServiceJWTManager
from users.service_loader import get_service_loader, reload_service_accounts
from users.permissions import require_service_permission, ServicePermissionChecker
from users.service_auth import get_service_context
from users.service_registry import get_service_registry


class GenerateServiceTokenMutation(graphene.Mutation):
    """Generate a service authentication token."""
    
    class Arguments:
        service_id = graphene.String(required=True, description="Service ID requesting the token")
        target_service = graphene.String(description="Target service for scoped access")
        requested_permissions = graphene.List(graphene.String, description="Specific permissions for this token")

    service_token = graphene.String()
    expires_in = graphene.Int()
    token_type = graphene.String()
    scoped_permissions = graphene.List(graphene.String)
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, service_id, target_service=None, requested_permissions=None):
        # This mutation can be called by OPERATIONS users or by the service itself
        service_context = get_service_context(info)
        current_user = info.context.user
        
        # Check authorization
        if service_context.is_service_authenticated:
            # Service requesting token for itself or another service
            if service_context.service_id != service_id:
                # Service requesting token for another service - need special permission
                service_context.require_permission('generate_tokens:services')
        elif current_user.is_authenticated and current_user.is_operations_user():
            # OPERATIONS user can generate tokens for any service
            pass
        else:
            raise GraphQLError("Authorization required: OPERATIONS user or authenticated service")

        try:
            # Get the service account
            service_account = ServiceAccount.objects.get(
                service_id=service_id,
                is_active=True
            )
            
            # Generate token
            additional_claims = {}
            if requested_permissions:
                additional_claims['requested_permissions'] = requested_permissions
            
            token = ServiceJWTManager.create_service_token(
                service_account,
                target_service=target_service,
                additional_claims=additional_claims
            )
            
            # Get token info
            token_info = ServiceJWTManager.get_service_info_from_token(token)
            expires_in = ServiceJWTManager.SERVICE_TOKEN_LIFETIME_MINUTES * 60  # Convert to seconds
            
            # Determine scoped permissions
            scoped_permissions = service_account.permissions
            if target_service:
                scoped_permissions = [
                    perm for perm in service_account.permissions 
                    if perm.startswith(f'{target_service}:') or ':' not in perm
                ]
            
            return GenerateServiceTokenMutation(
                service_token=token,
                expires_in=expires_in,
                token_type='service',
                scoped_permissions=scoped_permissions,
                success=True,
                message=f"Successfully generated service token for {service_id}"
            )

        except ServiceAccount.DoesNotExist:
            raise GraphQLError(f"Service account {service_id} not found or inactive")
        except Exception as e:
            raise GraphQLError(f"Error generating service token: {str(e)}")


class ValidateServiceTokenMutation(graphene.Mutation):
    """Validate a service authentication token."""
    
    class Arguments:
        token = graphene.String(required=True, description="Service token to validate")
        required_service_type = graphene.String(description="Required service type")
        required_permissions = graphene.List(graphene.String, description="Required permissions")

    valid = graphene.Boolean()
    service_id = graphene.String()
    service_type = graphene.String()
    permissions = graphene.List(graphene.String)
    expires_at = graphene.Int()
    target_service = graphene.String()
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    @require_service_permission('validate_tokens:services')
    def mutate(root, info, token, required_service_type=None, required_permissions=None):
        try:
            # Validate the token
            payload = ServiceJWTManager.validate_service_token(
                token,
                required_service_type=required_service_type,
                required_permissions=required_permissions
            )
            
            return ValidateServiceTokenMutation(
                valid=True,
                service_id=payload.get('sub'),
                service_type=payload.get('service_type'),
                permissions=payload.get('permissions', []),
                expires_at=payload.get('exp'),
                target_service=payload.get('target_service'),
                success=True,
                message="Token validation successful"
            )

        except Exception as e:
            return ValidateServiceTokenMutation(
                valid=False,
                success=False,
                message=f"Token validation failed: {str(e)}"
            )


class CreateServiceToServiceTokenMutation(graphene.Mutation):
    """Create a token for service-to-service communication."""
    
    class Arguments:
        target_service_id = graphene.String(required=True, description="Target service ID")
        permissions = graphene.List(graphene.String, description="Specific permissions for this interaction")

    service_token = graphene.String()
    expires_in = graphene.Int()
    target_service = graphene.String()
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, target_service_id, permissions=None):
        # Must be called by an authenticated service
        service_context = get_service_context(info)
        
        if not service_context.is_service_authenticated:
            raise GraphQLError("Service authentication required")
        
        # Check if service has permission to communicate with target service
        service_context.require_permission(f'communicate:{target_service_id}')
        
        try:
            # Generate service-to-service token
            token = ServiceJWTManager.create_service_to_service_token(
                service_context.service_id,
                target_service_id,
                permissions=permissions
            )
            
            expires_in = ServiceJWTManager.SERVICE_TOKEN_LIFETIME_MINUTES * 60
            
            return CreateServiceToServiceTokenMutation(
                service_token=token,
                expires_in=expires_in,
                target_service=target_service_id,
                success=True,
                message=f"Successfully created service-to-service token for {target_service_id}"
            )

        except Exception as e:
            raise GraphQLError(f"Error creating service-to-service token: {str(e)}")


class ReloadServiceAccountsMutation(graphene.Mutation):
    """Reload service accounts from environment variables."""
    
    class Arguments:
        force_update = graphene.Boolean(default_value=False, description="Force update existing service accounts")

    success = graphene.Boolean()
    message = graphene.String()
    created_count = graphene.Int()
    updated_count = graphene.Int()
    deactivated_count = graphene.Int()
    errors = graphene.List(graphene.String)
    load_time = graphene.Float()

    @staticmethod
    def mutate(root, info, force_update=False):
        # Check authorization - only OPERATIONS users or services with admin permissions
        service_context = get_service_context(info)
        current_user = info.context.user
        
        if service_context.is_service_authenticated:
            service_context.require_permission('admin:service_accounts')
        elif current_user.is_authenticated and current_user.is_operations_user():
            pass
        else:
            raise GraphQLError("Authorization required: OPERATIONS user or service with admin permissions")

        try:
            # Reload service accounts
            result = reload_service_accounts(force_update=force_update)
            
            return ReloadServiceAccountsMutation(
                success=result['success'],
                message="Service accounts reloaded successfully" if result['success'] else "Reload failed",
                created_count=result['created_count'],
                updated_count=result['updated_count'],
                deactivated_count=result['deactivated_count'],
                errors=result['errors'],
                load_time=result['load_time']
            )

        except Exception as e:
            return ReloadServiceAccountsMutation(
                success=False,
                message=f"Error reloading service accounts: {str(e)}",
                created_count=0,
                updated_count=0,
                deactivated_count=0,
                errors=[str(e)],
                load_time=0.0
            )


class GetServiceLoadStatusMutation(graphene.Mutation):
    """Get current service account load status."""

    auto_reload_enabled = graphene.Boolean()
    reload_interval = graphene.Int()
    last_load_time = graphene.String()
    config_hash = graphene.String()
    active_services_env = graphene.Int()
    total_services_db = graphene.Int()
    active_services_db = graphene.Int()
    reload_thread_alive = graphene.Boolean()
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info):
        # Check authorization
        service_context = get_service_context(info)
        current_user = info.context.user
        
        if service_context.is_service_authenticated:
            service_context.require_permission('read:service_accounts')
        elif current_user.is_authenticated and current_user.is_operations_user():
            pass
        else:
            raise GraphQLError("Authorization required: OPERATIONS user or authenticated service")

        try:
            loader = get_service_loader()
            status = loader.get_load_status()
            
            return GetServiceLoadStatusMutation(
                auto_reload_enabled=status['auto_reload_enabled'],
                reload_interval=status['reload_interval'],
                last_load_time=status['last_load_time'],
                config_hash=status['config_hash'],
                active_services_env=status['active_services_env'],
                total_services_db=status['total_services_db'],
                active_services_db=status['active_services_db'],
                reload_thread_alive=status['reload_thread_alive'],
                success=True,
                message="Service load status retrieved successfully"
            )

        except Exception as e:
            return GetServiceLoadStatusMutation(
                success=False,
                message=f"Error getting service load status: {str(e)}"
            )


class RegisterServiceMutation(graphene.Mutation):
    """Register a service in the service registry."""

    class Arguments:
        service_id = graphene.String(required=True, description="Service ID to register")
        capabilities = graphene.JSONString(description="Service capabilities and features")
        health_endpoint = graphene.String(description="Health check endpoint URL")
        metadata = graphene.JSONString(description="Additional service metadata")

    success = graphene.Boolean()
    message = graphene.String()
    service_info = graphene.JSONString()

    @staticmethod
    def mutate(root, info, service_id, capabilities=None, health_endpoint=None, metadata=None):
        # Must be called by the service itself or OPERATIONS user
        service_context = get_service_context(info)
        current_user = info.context.user

        if service_context.is_service_authenticated:
            # Service can only register itself
            if service_context.service_id != service_id:
                raise GraphQLError("Service can only register itself")
        elif current_user.is_authenticated and current_user.is_operations_user():
            # OPERATIONS user can register any service
            pass
        else:
            raise GraphQLError("Authorization required: service authentication or OPERATIONS user")

        try:
            registry = get_service_registry()
            success = registry.register_service(
                service_id=service_id,
                capabilities=capabilities,
                health_endpoint=health_endpoint,
                metadata=metadata
            )

            if success:
                service_info = registry.get_service_info(service_id)
                return RegisterServiceMutation(
                    success=True,
                    message=f"Successfully registered service: {service_id}",
                    service_info=service_info
                )
            else:
                return RegisterServiceMutation(
                    success=False,
                    message=f"Failed to register service: {service_id}"
                )

        except Exception as e:
            return RegisterServiceMutation(
                success=False,
                message=f"Error registering service: {str(e)}"
            )


class ServiceHeartbeatMutation(graphene.Mutation):
    """Send a heartbeat from a service."""

    class Arguments:
        health_status = graphene.JSONString(description="Current health status information")

    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, health_status=None):
        # Must be called by an authenticated service
        service_context = get_service_context(info)

        if not service_context.is_service_authenticated:
            raise GraphQLError("Service authentication required")

        try:
            registry = get_service_registry()
            success = registry.heartbeat(
                service_id=service_context.service_id,
                health_status=health_status
            )

            return ServiceHeartbeatMutation(
                success=success,
                message="Heartbeat recorded successfully" if success else "Failed to record heartbeat"
            )

        except Exception as e:
            return ServiceHeartbeatMutation(
                success=False,
                message=f"Error recording heartbeat: {str(e)}"
            )


class RegisterServiceMutation(graphene.Mutation):
    """Register a service in the service registry."""

    class Arguments:
        service_id = graphene.String(required=True, description="Service ID to register")
        capabilities = graphene.JSONString(description="Service capabilities and features")
        health_endpoint = graphene.String(description="Health check endpoint URL")
        metadata = graphene.JSONString(description="Additional service metadata")

    success = graphene.Boolean()
    message = graphene.String()
    service_info = graphene.JSONString()

    @staticmethod
    def mutate(root, info, service_id, capabilities=None, health_endpoint=None, metadata=None):
        # Must be called by the service itself or OPERATIONS user
        service_context = get_service_context(info)
        current_user = info.context.user

        if service_context.is_service_authenticated:
            # Service can only register itself
            if service_context.service_id != service_id:
                raise GraphQLError("Service can only register itself")
        elif current_user.is_authenticated and current_user.is_operations_user():
            # OPERATIONS user can register any service
            pass
        else:
            raise GraphQLError("Authorization required: service authentication or OPERATIONS user")

        try:
            registry = get_service_registry()
            success = registry.register_service(
                service_id=service_id,
                capabilities=capabilities,
                health_endpoint=health_endpoint,
                metadata=metadata
            )

            if success:
                service_info = registry.get_service_info(service_id)
                return RegisterServiceMutation(
                    success=True,
                    message=f"Successfully registered service: {service_id}",
                    service_info=service_info
                )
            else:
                return RegisterServiceMutation(
                    success=False,
                    message=f"Failed to register service: {service_id}"
                )

        except Exception as e:
            return RegisterServiceMutation(
                success=False,
                message=f"Error registering service: {str(e)}"
            )


class ServiceHeartbeatMutation(graphene.Mutation):
    """Send a heartbeat from a service."""

    class Arguments:
        health_status = graphene.JSONString(description="Current health status information")

    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, health_status=None):
        # Must be called by an authenticated service
        service_context = get_service_context(info)

        if not service_context.is_service_authenticated:
            raise GraphQLError("Service authentication required")

        try:
            registry = get_service_registry()
            success = registry.heartbeat(
                service_id=service_context.service_id,
                health_status=health_status
            )

            return ServiceHeartbeatMutation(
                success=success,
                message="Heartbeat recorded successfully" if success else "Failed to record heartbeat"
            )

        except Exception as e:
            return ServiceHeartbeatMutation(
                success=False,
                message=f"Error recording heartbeat: {str(e)}"
            )


class UnregisterServiceMutation(graphene.Mutation):
    """Unregister a service from the registry."""

    class Arguments:
        service_id = graphene.String(required=True, description="Service ID to unregister")

    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, service_id):
        # Must be called by the service itself or OPERATIONS user
        service_context = get_service_context(info)
        current_user = info.context.user

        if service_context.is_service_authenticated:
            # Service can only unregister itself
            if service_context.service_id != service_id:
                raise GraphQLError("Service can only unregister itself")
        elif current_user.is_authenticated and current_user.is_operations_user():
            # OPERATIONS user can unregister any service
            pass
        else:
            raise GraphQLError("Authorization required: service authentication or OPERATIONS user")

        try:
            registry = get_service_registry()
            success = registry.unregister_service(service_id)

            return UnregisterServiceMutation(
                success=success,
                message=f"Successfully unregistered service: {service_id}" if success else f"Service {service_id} was not registered"
            )

        except Exception as e:
            return UnregisterServiceMutation(
                success=False,
                message=f"Error unregistering service: {str(e)}"
            )


class UnregisterServiceMutation(graphene.Mutation):
    """Unregister a service from the registry."""

    class Arguments:
        service_id = graphene.String(required=True, description="Service ID to unregister")

    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, service_id):
        # Must be called by the service itself or OPERATIONS user
        service_context = get_service_context(info)
        current_user = info.context.user

        if service_context.is_service_authenticated:
            # Service can only unregister itself
            if service_context.service_id != service_id:
                raise GraphQLError("Service can only unregister itself")
        elif current_user.is_authenticated and current_user.is_operations_user():
            # OPERATIONS user can unregister any service
            pass
        else:
            raise GraphQLError("Authorization required: service authentication or OPERATIONS user")

        try:
            registry = get_service_registry()
            success = registry.unregister_service(service_id)

            return UnregisterServiceMutation(
                success=success,
                message=f"Successfully unregistered service: {service_id}" if success else f"Service {service_id} was not registered"
            )

        except Exception as e:
            return UnregisterServiceMutation(
                success=False,
                message=f"Error unregistering service: {str(e)}"
            )
