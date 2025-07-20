import graphene
from graphql import GraphQLError
from .types import UserType, ServiceAccountType, OrganizationContextType
from ..models import ServiceAccount, OrganizationContext
from ..service_auth import get_service_context
from ..permissions import require_service_permission, check_service_or_user_permission

class UserQuery(graphene.ObjectType):
    """GraphQL queries related to users."""
    me = graphene.Field(UserType)

    # Service Account Queries
    service_accounts = graphene.List(
        ServiceAccountType,
        description="List all service accounts (OPERATIONS users only)"
    )
    service_account = graphene.Field(
        ServiceAccountType,
        service_id=graphene.String(required=True),
        description="Get a specific service account by ID (OPERATIONS users only)"
    )

    # Organization Context Queries
    organization_contexts = graphene.List(
        OrganizationContextType,
        organization_id=graphene.String(),
        description="List organization contexts, optionally filtered by organization ID"
    )
    organization_context = graphene.Field(
        OrganizationContextType,
        id=graphene.ID(required=True),
        description="Get a specific organization context by ID"
    )

    # Service authentication queries
    my_service_info = graphene.Field(
        ServiceAccountType,
        description="Get information about the current authenticated service"
    )
    service_permissions = graphene.JSONString(
        description="Get permissions for the current authenticated service"
    )
    validate_service_permission = graphene.JSONString(
        permission=graphene.String(required=True),
        resource_id=graphene.String(),
        description="Validate if current service has a specific permission"
    )

    def resolve_me(root, info):
        user = info.context.user
        if user.is_authenticated:
            return user
        return None

    def resolve_service_accounts(root, info):
        """List all service accounts (OPERATIONS users only)."""
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("Authentication required")

        if not (user.is_operations_user() or user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can view service accounts")

        return ServiceAccount.objects.all().order_by('service_id')

    def resolve_service_account(root, info, service_id):
        """Get a specific service account by ID (OPERATIONS users only)."""
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("Authentication required")

        if not (user.is_operations_user() or user.is_superuser):
            raise GraphQLError("Only OPERATIONS users or superusers can view service accounts")

        try:
            return ServiceAccount.objects.get(service_id=service_id)
        except ServiceAccount.DoesNotExist:
            raise GraphQLError(f"Service account with ID {service_id} not found")

    def resolve_organization_contexts(root, info, organization_id=None):
        """List organization contexts, optionally filtered by organization ID."""
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("Authentication required")

        # Only OPERATIONS users can see all contexts, others see their own organization's contexts
        queryset = OrganizationContext.objects.filter(is_active=True)

        if organization_id:
            queryset = queryset.filter(organization_id=organization_id)
        elif not (user.is_operations_user() or user.is_superuser):
            # Regular users can only see their organization's contexts
            # This would need to be implemented based on your organization model
            raise GraphQLError("Access denied: insufficient permissions")

        return queryset.order_by('organization_id', 'branch_id', 'cluster_id')

    def resolve_organization_context(root, info, id):
        """Get a specific organization context by ID."""
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("Authentication required")

        try:
            context = OrganizationContext.objects.get(id=id, is_active=True)

            # Check permissions
            if not (user.is_operations_user() or user.is_superuser):
                # Regular users can only see their organization's contexts
                # This would need to be implemented based on your organization model
                raise GraphQLError("Access denied: insufficient permissions")

            return context
        except OrganizationContext.DoesNotExist:
            raise GraphQLError(f"Organization context with ID {id} not found")

    # Service-specific queries
    def resolve_my_service_info(root, info):
        """Get information about the current authenticated service."""
        service_context = get_service_context(info)

        if not service_context.is_service_authenticated:
            raise GraphQLError("Service authentication required")

        return service_context.service_account

    def resolve_service_permissions(root, info):
        """Get permissions for the current authenticated service."""
        service_context = get_service_context(info)

        if not service_context.is_service_authenticated:
            raise GraphQLError("Service authentication required")

        return {
            'service_id': service_context.service_id,
            'service_type': service_context.service_type,
            'permissions': service_context.permissions,
            'scoped_permissions': service_context.scoped_permissions,
            'target_service': service_context.target_service
        }

    def resolve_validate_service_permission(root, info, permission, resource_id=None):
        """Validate if current service has a specific permission."""
        service_context = get_service_context(info)

        if not service_context.is_service_authenticated:
            return {
                'has_permission': False,
                'error': 'Service authentication required'
            }

        has_permission = service_context.has_permission(permission)

        return {
            'has_permission': has_permission,
            'permission': permission,
            'resource_id': resource_id,
            'service_id': service_context.service_id
        }
