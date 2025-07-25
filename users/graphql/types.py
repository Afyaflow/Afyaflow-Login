import graphene
from graphene_django import DjangoObjectType
from ..models import User, ServiceAccount, OrganizationContext

class UserType(DjangoObjectType):
    """GraphQL type for the User model, representing a healthcare professional or system user."""
    totp_mfa_enabled = graphene.Boolean(source='mfa_totp_setup_complete', description="True if TOTP MFA is configured and verified.")
    sms_mfa_enabled = graphene.Boolean(source='mfa_sms_enabled', description="True if SMS MFA is enabled.")
    email_mfa_enabled = graphene.Boolean(source='mfa_email_enabled', description="True if Email MFA is enabled.")

    # Role-related fields
    primary_role = graphene.String(source='get_primary_role_name', description="The user's primary role (PATIENT, PROVIDER, ADMIN)")
    roles = graphene.List(graphene.String, description="List of all active roles for this user")

    # Enhanced email field that handles phone-based users
    email = graphene.String(description="User's email address (null for phone-only users)")
    is_phone_only_user = graphene.Boolean(description="True if user registered with phone number only")

    def resolve_email(self, info):
        """Return email only if it's a real email, not a phone-based identifier."""
        if self.email and '@phone.afyaflow.local' in self.email:
            return None  # Don't expose phone-based email identifiers
        return self.email

    def resolve_is_phone_only_user(self, info):
        """Check if this user registered with phone number only."""
        return self.email and '@phone.afyaflow.local' in self.email

    def resolve_roles(self, info):
        """Return list of active role names for this user."""
        return [role.name for role in self.get_active_roles()]

    class Meta:
        model = User
        fields = (
            "id", "first_name", "last_name", "is_active", "is_staff",
            "is_superuser", "is_suspended", "date_joined", "last_login",
            "email_verified",
            "phone_number", "phone_number_verified",
            "primary_role", "roles", "email", "is_phone_only_user"  # Enhanced fields
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
    user = graphene.Field(lambda: UserType, required=True)

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
    """
    Payload returned after a login or registration attempt.
    If MFA is not required, tokens will be provided.
    If MFA is required, the 'mfaRequired' flag will be true, and the client must complete the second step.
    Enhanced to support both legacy and gateway-compliant token formats.
    """
    user = graphene.Field(UserType, description="The authenticated user object.")
    access_token = graphene.String(name="accessToken", required=False, description="JWT access token. Null if MFA is required.")
    refresh_token = graphene.String(name="refreshToken", required=False, description="JWT refresh token. Null if MFA is required.")

    # New fields for MFA Flow Control
    mfa_required = graphene.Boolean(name="mfaRequired", description="True if an MFA step is required to complete login.")
    mfa_token = graphene.String(name="mfaToken", required=False, description="A short-lived token to use in the verifyMfa mutation. Provided only when MFA is required.")
    enabled_mfa_methods = graphene.List(graphene.String, name="enabledMfaMethods", required=False, description="A list of MFA methods enabled for the user (e.g., ['TOTP', 'SMS']).")

    organization_memberships = graphene.List(OrganizationMembershipType, name="organizationMemberships", required=False, description="A list of organizations the user is a member of.")
    errors = graphene.List(graphene.String, description="List of error messages if any operation within the mutation fails.")

    # Gateway-compliant token fields
    token_type = graphene.String(name="tokenType", required=False, description="Token type (e.g., 'Bearer')")
    expires_in = graphene.Int(name="expiresIn", required=False, description="Token expiration time in seconds")
    token_format = graphene.String(name="tokenFormat", required=False, description="Token format: 'legacy', 'gateway_compliant', or 'dual'")
    user_type = graphene.String(name="userType", required=False, description="User type: 'patient', 'provider', or 'operations'")

    # Organization Context Token for providers
    org_context_token = graphene.String(name="orgContextToken", required=False, description="Organization Context Token (OCT) for providers")

    # Legacy token support during migration
    legacy_access_token = graphene.String(name="legacyAccessToken", required=False, description="Legacy format access token for backward compatibility")
    legacy_refresh_token = graphene.String(name="legacyRefreshToken", required=False, description="Legacy format refresh token for backward compatibility")

    # Migration support
    deprecation_warning = graphene.String(name="deprecationWarning", required=False, description="Warning message about deprecated token format")

class MfaChallengeType(graphene.ObjectType):
    """DEPRECATED: This will be removed in favor of the enhanced AuthPayloadType."""
    mfa_required = graphene.Boolean(default_value=True, description="Confirms that MFA is required.")
    mfa_token = graphene.String(description="A short-lived token to be used in the verifyMfa mutation.")
    message = graphene.String(description="A message to the user, e.g., indicating where OTPs were sent.")

class LoginPayload(graphene.Union):
    """DEPRECATED: This will be removed in favor of the enhanced AuthPayloadType."""
    class Meta:
        types = (AuthPayloadType, MfaChallengeType)

class GetScopedAccessTokenPayload(graphene.Union):
    """Defines the possible return types for the getScopedAccessToken mutation."""
    class Meta:
        types = (ScopedAuthPayload,)
        # In the future, we can add custom error types here.
        # e.g. types = (ScopedAuthPayload, PermissionsError, InvalidOrganizationError)


class ServiceAccountType(DjangoObjectType):
    """GraphQL type for the ServiceAccount model."""

    class Meta:
        model = ServiceAccount
        fields = (
            "id", "service_id", "service_type", "permissions",
            "is_active", "created_at", "updated_at"
        )
        description = "Represents a service account for inter-service authentication."


class OrganizationContextType(DjangoObjectType):
    """GraphQL type for the OrganizationContext model."""

    full_context = graphene.JSONString(description="Complete organization context for OCT token")

    def resolve_full_context(self, info):
        """Return the full organization context."""
        return self.get_full_context()

    class Meta:
        model = OrganizationContext
        fields = (
            "id", "organization_id", "branch_id", "cluster_id",
            "subscribed_services", "organization_permissions",
            "is_active", "created_at", "updated_at", "full_context"
        )
        description = "Represents organization context for OCT tokens."
