"""
GraphQL mutations for Organization Context Token (OCT) management.
"""

import graphene
from graphql import GraphQLError
from django.db import transaction
from django.conf import settings

from users.models import User, OrganizationContext
from users.gateway_jwt import GatewayJWTManager
from users.graphql.types import OrganizationContextType


class CreateOrganizationContextMutation(graphene.Mutation):
    """Create a new organization context for OCT generation."""
    
    class Arguments:
        organization_id = graphene.String(required=True, description="Organization UUID")
        branch_id = graphene.String(description="Branch UUID within the organization")
        cluster_id = graphene.String(description="Cluster UUID for regional grouping")
        subscribed_services = graphene.List(graphene.String, required=True, description="List of services this organization has access to")
        organization_permissions = graphene.JSONString(required=True, description="Organization-specific permissions mapping")

    organization_context = graphene.Field(OrganizationContextType)
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, organization_id, subscribed_services, organization_permissions, 
               branch_id=None, cluster_id=None):
        # Check if user is authorized
        current_user = info.context.user
        if not current_user.is_authenticated:
            raise GraphQLError("Authentication required")
        
        if not (current_user.is_operations_user() or current_user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can create organization contexts")

        try:
            with transaction.atomic():
                # Create organization context
                org_context = OrganizationContext.objects.create(
                    organization_id=organization_id,
                    branch_id=branch_id,
                    cluster_id=cluster_id,
                    subscribed_services=subscribed_services,
                    organization_permissions=organization_permissions,
                    is_active=True
                )

                return CreateOrganizationContextMutation(
                    organization_context=org_context,
                    success=True,
                    message=f"Successfully created organization context for {organization_id}"
                )

        except Exception as e:
            raise GraphQLError(f"Error creating organization context: {str(e)}")


class GetOrganizationContextTokenMutation(graphene.Mutation):
    """Generate an Organization Context Token (OCT) for a provider."""
    
    class Arguments:
        organization_context_id = graphene.ID(required=True, description="Organization context ID")

    org_context_token = graphene.String()
    expires_in = graphene.Int()
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, organization_context_id):
        # Check if user is authenticated
        current_user = info.context.user
        if not current_user.is_authenticated:
            raise GraphQLError("Authentication required")
        
        # Check if user is a provider
        if not current_user.is_provider():
            raise GraphQLError("Organization Context Tokens can only be generated for providers")

        try:
            # Get organization context
            org_context = OrganizationContext.objects.get(
                id=organization_context_id,
                is_active=True
            )
            
            # TODO: Add authorization check to ensure provider has access to this organization
            # This would typically involve checking if the provider is a member of the organization
            
            # Generate OCT
            oct_token = GatewayJWTManager.create_organization_context_token(
                current_user, 
                org_context
            )
            
            # Get token lifetime
            expires_in = getattr(settings, 'OCT_TOKEN_LIFETIME', 15) * 60  # Convert to seconds
            
            return GetOrganizationContextTokenMutation(
                org_context_token=oct_token,
                expires_in=expires_in,
                success=True,
                message="Successfully generated Organization Context Token"
            )

        except OrganizationContext.DoesNotExist:
            raise GraphQLError(f"Organization context with ID {organization_context_id} not found")
        except Exception as e:
            raise GraphQLError(f"Error generating OCT: {str(e)}")


class UpdateOrganizationContextMutation(graphene.Mutation):
    """Update an existing organization context."""
    
    class Arguments:
        organization_context_id = graphene.ID(required=True, description="Organization context ID")
        subscribed_services = graphene.List(graphene.String, description="Updated list of services")
        organization_permissions = graphene.JSONString(description="Updated organization-specific permissions")
        is_active = graphene.Boolean(description="Whether the context is active")

    organization_context = graphene.Field(OrganizationContextType)
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, organization_context_id, subscribed_services=None, 
               organization_permissions=None, is_active=None):
        # Check if user is authorized
        current_user = info.context.user
        if not current_user.is_authenticated:
            raise GraphQLError("Authentication required")
        
        if not (current_user.is_operations_user() or current_user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can update organization contexts")

        try:
            # Get organization context
            org_context = OrganizationContext.objects.get(id=organization_context_id)
            
            # Update fields if provided
            if subscribed_services is not None:
                org_context.subscribed_services = subscribed_services
            if organization_permissions is not None:
                org_context.organization_permissions = organization_permissions
            if is_active is not None:
                org_context.is_active = is_active
            
            org_context.save()

            return UpdateOrganizationContextMutation(
                organization_context=org_context,
                success=True,
                message=f"Successfully updated organization context {organization_context_id}"
            )

        except OrganizationContext.DoesNotExist:
            raise GraphQLError(f"Organization context with ID {organization_context_id} not found")
        except Exception as e:
            raise GraphQLError(f"Error updating organization context: {str(e)}")


class ValidateTokensMutation(graphene.Mutation):
    """Validate auth token and OCT for testing purposes."""
    
    class Arguments:
        auth_token = graphene.String(required=True, description="Auth token to validate")
        org_context_token = graphene.String(description="Organization context token to validate")

    auth_token_valid = graphene.Boolean()
    oct_token_valid = graphene.Boolean()
    auth_payload = graphene.JSONString()
    oct_payload = graphene.JSONString()
    user_type = graphene.String()
    organization_id = graphene.String()
    success = graphene.Boolean()
    message = graphene.String()

    @staticmethod
    def mutate(root, info, auth_token, org_context_token=None):
        # Check if user is authorized (only for testing/debugging)
        current_user = info.context.user
        if not current_user.is_authenticated:
            raise GraphQLError("Authentication required")
        
        if not (current_user.is_operations_user() or current_user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can validate tokens")

        result = {
            'auth_token_valid': False,
            'oct_token_valid': False,
            'auth_payload': None,
            'oct_payload': None,
            'user_type': None,
            'organization_id': None,
            'success': False,
            'message': ''
        }

        try:
            # Validate auth token
            auth_payload = GatewayJWTManager.validate_auth_token(auth_token)
            result['auth_token_valid'] = True
            result['auth_payload'] = auth_payload
            result['user_type'] = auth_payload.get('user_type')
            
            # Validate OCT if provided
            if org_context_token:
                oct_payload = GatewayJWTManager.validate_organization_context_token(org_context_token)
                result['oct_token_valid'] = True
                result['oct_payload'] = oct_payload
                result['organization_id'] = oct_payload.get('orgId')
            
            result['success'] = True
            result['message'] = "Token validation completed successfully"
            
            return ValidateTokensMutation(**result)

        except Exception as e:
            result['message'] = f"Token validation failed: {str(e)}"
            return ValidateTokensMutation(**result)
