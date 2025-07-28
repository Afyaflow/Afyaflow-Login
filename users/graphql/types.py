import graphene
from graphene_django import DjangoObjectType
from ..models import User

class UserType(DjangoObjectType):
    """GraphQL type for the User model, representing a healthcare professional, patient, or operations user."""
    totp_mfa_enabled = graphene.Boolean(source='mfa_totp_setup_complete', description="True if TOTP MFA is configured and verified.")
    sms_mfa_enabled = graphene.Boolean(source='mfa_sms_enabled', description="True if SMS MFA is enabled.")
    email_mfa_enabled = graphene.Boolean(source='mfa_email_enabled', description="True if Email MFA is enabled.")

    class Meta:
        model = User
        fields = (
            "id", "email", "first_name", "last_name", "is_active", "is_staff",
            "is_superuser", "is_suspended", "date_joined", "last_login",
            "email_verified", "user_type",
            "phone_number", "phone_number_verified"
        )
        description = "Represents a user within the Afyaflow system (provider, patient, or operations)."
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

class PatientOTPResponse(graphene.ObjectType):
    """Response type for patient OTP initiation."""
    success = graphene.Boolean(required=True, description="Whether the OTP was successfully sent.")
    message = graphene.String(required=True, description="Human-readable message about the operation.")
    otp_sent = graphene.Boolean(required=True, description="Whether an OTP was sent to the identifier.")
    expires_at = graphene.DateTime(description="When the OTP expires (if sent).")
    identifier_type = graphene.String(description="Type of identifier used (email or phone).")


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
