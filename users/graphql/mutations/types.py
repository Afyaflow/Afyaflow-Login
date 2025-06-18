import graphene
from ...models import User, RefreshToken

class MfaChallengeType(graphene.ObjectType):
    """Indicates that a Multi-Factor Authentication challenge has been issued."""
    mfa_required = graphene.Boolean(default_value=True, description="Confirms that MFA is required.")
    mfa_token = graphene.String(description="A short-lived token to be used in the verifyMfa mutation.")
    message = graphene.String(description="A message to the user, e.g., indicating where OTPs were sent.")

class AuthPayloadType(graphene.ObjectType):
    # ... (existing AuthPayloadType)

class LoginPayload(graphene.Union):
    class Meta:
        types = (AuthPayloadType, MfaChallengeType) 