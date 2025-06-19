import graphene
from graphene_django import DjangoObjectType
from ..models import User

class UserType(DjangoObjectType):
    """GraphQL type for the User model, representing a healthcare professional or system user."""
    class Meta:
        model = User
        fields = (
            "id", "email", "first_name", "last_name", "is_active", "is_staff",
            "is_superuser", "is_suspended", "date_joined", "last_login",
            "mfa_totp_setup_complete", "mfa_email_enabled", "mfa_sms_enabled",
            "phone_number", "phone_number_verified"
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

class ScopedAuthPayload(graphene.ObjectType):
    """Payload containing the Organization Context Token (OCT) and permissions for a specific organization."""
    oct = graphene.String(required=True, name="organizationContextToken", description="JWT containing the user's context and permissions for the selected organization.")
    permissions = graphene.List(graphene.String, required=True, description="A list of permission strings granted to the user in the context of the selected organization.")
    user = graphene.Field(lambda: UserType, required=True)

    def resolve_user(self, info):
        # This resolver will be called by the gateway after it resolves the user from the auth service.
        # The user object is expected to be on the root of the resolved object from the upstream service.
        return self

class OrganizationStub(graphene.ObjectType):
    """Represents an Organization entity, resolved by the Organization subgraph."""
    id = graphene.UUID(required=True, description="The unique identifier of the organization.")
    name = graphene.String(required=True, description="The name of the organization.")
   
    @classmethod
    def __resolve_reference(cls, info, **data):
        # This stub is primarily for linking. The actual data is resolved by the Organization service.
        return OrganizationStub(id=data.get('id'))

class OrganizationMembershipType(graphene.ObjectType):
    """Represents basic information about an organization a user is a member of."""
    organization = graphene.Field(OrganizationStub, name="organization", required=True, description="The organization the user is a member of.")
    # Imight include the user's role in this organization.

class AuthPayloadType(graphene.ObjectType):
    """Payload returned after successful authentication (login or register)."""
    user = graphene.Field(UserType, description="The authenticated user object.")
    access_token = graphene.String(name="accessToken", description="JWT access token for authenticated requests.")
    refresh_token = graphene.String(name="refreshToken", description="JWT refresh token to obtain new access tokens.")
    organization_context_token = graphene.String(name="organizationContextToken", required=False, description="JWT containing the user's context and permissions within a selected organization.")
    organization_context = graphene.Field(OrganizationStub, name="organizationContext", required=False, description="Context of the organization if specified. Resolved by the Organization service.")
    organization_memberships = graphene.List(OrganizationMembershipType, name="organizationMemberships", required=False, description="A list of organizations the user is a member of.")
    errors = graphene.List(graphene.String, description="List of error messages if any operation within the mutation fails.") # Added to Login, Register

class MfaChallengeType(graphene.ObjectType):
    """Indicates that a Multi-Factor Authentication challenge has been issued."""
    mfa_required = graphene.Boolean(default_value=True, description="Confirms that MFA is required.")
    mfa_token = graphene.String(description="A short-lived token to be used in the verifyMfa mutation.")
    message = graphene.String(description="A message to the user, e.g., indicating where OTPs were sent.")

class LoginPayload(graphene.Union):
    class Meta:
        types = (AuthPayloadType, MfaChallengeType)

class GetScopedAccessTokenPayload(graphene.Union):
    """Defines the possible return types for the getScopedAccessToken mutation."""
    class Meta:
        types = (ScopedAuthPayload,)
        # In the future, we can add custom error types here.
        # e.g. types = (ScopedAuthPayload, PermissionsError, InvalidOrganizationError)
