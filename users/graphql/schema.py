import graphene
from graphene_federation import LATEST_VERSION, build_schema

from .queries import UserQuery
from .mutations.auth import (
    RegisterMutation,
    LoginMutation,
    RefreshTokenMutation,
    LogoutMutation,
    LoginWithGoogleMutation,
)
from .mutations.profile import (
    UpdateProfileMutation,
    ChangePasswordMutation,
    RequestPasswordResetMutation,
    ResetPasswordMutation,
)
from .mutations.mfa import (
    InitiateMFASetupMutation,
    VerifyMFASetupMutation,
    DisableMFAMutation,
)

class UserMutation(graphene.ObjectType):
    """Root mutation for user-related actions."""
    register = RegisterMutation.Field()
    login = LoginMutation.Field()
    refresh_token = RefreshTokenMutation.Field()
    logout = LogoutMutation.Field()
    login_with_google = LoginWithGoogleMutation.Field(description="Logs in or registers a user using a Google ID Token.")
    
    update_profile = UpdateProfileMutation.Field()
    change_password = ChangePasswordMutation.Field()
    request_password_reset = RequestPasswordResetMutation.Field()
    reset_password = ResetPasswordMutation.Field()
    
    initiate_mfa_setup = InitiateMFASetupMutation.Field(description="Initiates the MFA setup process for the authenticated user.")
    verify_mfa_setup = VerifyMFASetupMutation.Field(description="Verifies the OTP code and enables MFA for the user.")
    disable_mfa = DisableMFAMutation.Field(description="Disables MFA for the authenticated user after verification.")


# Build the federated schema
schema = build_schema(query=UserQuery, mutation=UserMutation, federation_version=LATEST_VERSION)
