import graphene
from graphene_django import DjangoObjectType
from graphene_federation import key, external
from ..models import User


@key(fields="id")
class UserType(DjangoObjectType):
    """GraphQL type for the User model, representing a healthcare professional or system user."""
    class Meta:
        model = User
        fields = (
            "id", 
            "email", 
            "first_name", 
            "last_name", 
            "is_active", 
            "is_staff", 
            "is_superuser", 
            "is_suspended", 
            "mfa_enabled", 
            "date_joined", 
            "last_login"
        )
        description = "Represents a user within the Afyaflow system."
        # You can also use exclude = ("password", "other_sensitive_fields")

    @classmethod
    def __resolve_reference(cls, info, **data):
        user_id = data.get('id')
        if user_id is None:
            return None
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

@key(fields="id", resolvable=False) # This subgraph cannot resolve an Organization by its ID alone
class OrganizationStub(graphene.ObjectType):
    """Represents an Organization entity, resolved by the Organization subgraph."""
    id = graphene.UUID(required=True, description="The unique identifier of the organization.")
   
    @classmethod
    def __resolve_reference(cls, info, **data):
        # This stub is primarily for linking. The actual data is resolved by the Organization service.
        return OrganizationStub(id=data.get('id'))

class OrganizationMembershipInfoType(graphene.ObjectType):
    """Represents basic information about an organization a user is a member of."""
    id = graphene.UUID(required=True, description="The unique identifier of the organization.")
    name = graphene.String(required=True, description="The name of the organization.")
    # Imight include the user's role in this organization.

class AuthPayloadType(graphene.ObjectType):
    """Payload returned after successful authentication (login or register)."""
    user = graphene.Field(UserType, description="The authenticated user object.")
    access_token = graphene.String(name="accessToken", description="JWT access token for authenticated requests.")
    refresh_token = graphene.String(name="refreshToken", description="JWT refresh token to obtain new access tokens.")
    organization_context_token = graphene.String(name="organizationContextToken", required=False, description="JWT containing the user's context and permissions within a selected organization.")
    organization_context = graphene.Field(OrganizationStub, name="organizationContext", required=False, description="Context of the organization if specified. Resolved by the Organization service.")
    organization_memberships = graphene.List(OrganizationMembershipInfoType, name="organizationMemberships", required=False, description="A list of organizations the user is a member of.")
    errors = graphene.List(graphene.String, description="List of error messages if any operation within the mutation fails.") # Added to Login, Register
