"""
GraphQL mutations for OPERATIONS user management and service account operations.
"""

import graphene
from django.contrib.auth import get_user_model
from django.db import transaction
from graphql import GraphQLError

from users.models import UserRole, UserRoleAssignment, ServiceAccount
from users.graphql.types import UserType, ServiceAccountType

User = get_user_model()


class CreateOperationsUserMutation(graphene.Mutation):
    """Create a new OPERATIONS user with system-wide administrative privileges."""
    
    class Arguments:
        email = graphene.String(required=True, description="Email address for the operations user")
        first_name = graphene.String(required=True, description="First name of the operations user")
        last_name = graphene.String(required=True, description="Last name of the operations user")
        password = graphene.String(required=True, description="Password for the operations user")

    user = graphene.Field(UserType)
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, email, first_name, last_name, password):
        # Check if user is authorized to create operations users
        current_user = info.context.user
        if not current_user.is_authenticated:
            raise GraphQLError("Authentication required")
        
        if not (current_user.is_operations_user() or current_user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can create OPERATIONS users")

        try:
            with transaction.atomic():
                # Check if user already exists
                if User.objects.filter(email=email).exists():
                    raise GraphQLError(f"User with email {email} already exists")

                # Get or create OPERATIONS role
                operations_role, created = UserRole.objects.get_or_create(
                    name='OPERATIONS',
                    defaults={
                        'description': 'Operations and system administration role with cross-tenant access',
                        'permissions': [
                            'view_all_users',
                            'view_system_logs',
                            'manage_system_settings',
                            'access_admin_interface',
                            'cross_tenant_access',
                            'system_maintenance',
                            'technical_support',
                            'service_account_management',
                            'global_monitoring'
                        ],
                        'is_active': True
                    }
                )

                # Create the user
                user = User.objects.create_user(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    password=password,
                    is_active=True,
                    email_verified=True  # Operations users are pre-verified
                )

                # Assign OPERATIONS role
                UserRoleAssignment.objects.create(
                    user=user,
                    role=operations_role,
                    assigned_by=current_user,
                    is_active=True
                )

                # Set as primary role
                user.primary_role = operations_role
                user.save(update_fields=['primary_role'])

                return CreateOperationsUserMutation(
                    user=user,
                    success=True,
                    message=f"Successfully created OPERATIONS user: {email}"
                )

        except Exception as e:
            raise GraphQLError(f"Error creating OPERATIONS user: {str(e)}")


class CreateServiceAccountMutation(graphene.Mutation):
    """Create a new service account for inter-service authentication."""
    
    class Arguments:
        service_id = graphene.String(required=True, description="Unique service identifier")
        service_type = graphene.String(required=True, description="Type of service")
        permissions = graphene.List(graphene.String, required=True, description="List of permissions")

    service_account = graphene.Field(ServiceAccountType)
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, service_id, service_type, permissions):
        # Check if user is authorized to create service accounts
        current_user = info.context.user
        if not current_user.is_authenticated:
            raise GraphQLError("Authentication required")
        
        if not (current_user.is_operations_user() or current_user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can create service accounts")

        try:
            # Check if service account already exists
            if ServiceAccount.objects.filter(service_id=service_id).exists():
                raise GraphQLError(f"Service account with ID {service_id} already exists")

            # Create the service account
            service_account = ServiceAccount.objects.create(
                service_id=service_id,
                service_type=service_type,
                permissions=permissions,
                is_active=True
            )

            return CreateServiceAccountMutation(
                service_account=service_account,
                success=True,
                message=f"Successfully created service account: {service_id}"
            )

        except Exception as e:
            raise GraphQLError(f"Error creating service account: {str(e)}")


class UpdateServiceAccountMutation(graphene.Mutation):
    """Update an existing service account."""
    
    class Arguments:
        service_id = graphene.String(required=True, description="Service identifier to update")
        service_type = graphene.String(description="New service type")
        permissions = graphene.List(graphene.String, description="New list of permissions")
        is_active = graphene.Boolean(description="Whether the service account is active")

    service_account = graphene.Field(ServiceAccountType)
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, service_id, service_type=None, permissions=None, is_active=None):
        # Check if user is authorized to update service accounts
        current_user = info.context.user
        if not current_user.is_authenticated:
            raise GraphQLError("Authentication required")
        
        if not (current_user.is_operations_user() or current_user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can update service accounts")

        try:
            # Get the service account
            service_account = ServiceAccount.objects.get(service_id=service_id)

            # Update fields if provided
            if service_type is not None:
                service_account.service_type = service_type
            if permissions is not None:
                service_account.permissions = permissions
            if is_active is not None:
                service_account.is_active = is_active

            service_account.save()

            return UpdateServiceAccountMutation(
                service_account=service_account,
                success=True,
                message=f"Successfully updated service account: {service_id}"
            )

        except ServiceAccount.DoesNotExist:
            raise GraphQLError(f"Service account with ID {service_id} not found")
        except Exception as e:
            raise GraphQLError(f"Error updating service account: {str(e)}")


class DeleteServiceAccountMutation(graphene.Mutation):
    """Delete a service account."""
    
    class Arguments:
        service_id = graphene.String(required=True, description="Service identifier to delete")

    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, service_id):
        # Check if user is authorized to delete service accounts
        current_user = info.context.user
        if not current_user.is_authenticated:
            raise GraphQLError("Authentication required")
        
        if not (current_user.is_operations_user() or current_user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can delete service accounts")

        try:
            # Get and delete the service account
            service_account = ServiceAccount.objects.get(service_id=service_id)
            service_account.delete()

            return DeleteServiceAccountMutation(
                success=True,
                message=f"Successfully deleted service account: {service_id}"
            )

        except ServiceAccount.DoesNotExist:
            raise GraphQLError(f"Service account with ID {service_id} not found")
        except Exception as e:
            raise GraphQLError(f"Error deleting service account: {str(e)}")


class LoadServiceAccountsFromEnvironmentMutation(graphene.Mutation):
    """Load service accounts from environment variables."""
    
    class Arguments:
        force_update = graphene.Boolean(default_value=False, description="Update existing service accounts")

    success = graphene.Boolean()
    message = graphene.String()
    created_count = graphene.Int()
    updated_count = graphene.Int()

    @staticmethod
    def mutate(root, info, force_update=False):
        # Check if user is authorized to load service accounts
        current_user = info.context.user
        if not current_user.is_authenticated:
            raise GraphQLError("Authentication required")
        
        if not (current_user.is_operations_user() or current_user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can load service accounts")

        try:
            # Use the ServiceAccount model's load_from_environment method
            created_count, updated_count = ServiceAccount.load_from_environment_with_counts(force_update)

            return LoadServiceAccountsFromEnvironmentMutation(
                success=True,
                message=f"Successfully loaded service accounts from environment",
                created_count=created_count,
                updated_count=updated_count
            )

        except Exception as e:
            raise GraphQLError(f"Error loading service accounts: {str(e)}")
