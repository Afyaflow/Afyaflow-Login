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
    InitiatePasswordResetMutation,
    ConfirmPasswordResetMutation,
)
from .mutations.mfa import (
    InitiateMFASetupMutation,
    VerifyMFASetupMutation,
    DisableMFAMutation,
    ToggleEmailMfaMutation,
    AddPhoneNumberMutation,
    VerifyPhoneNumberMutation,
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
    initiate_password_reset = InitiatePasswordResetMutation.Field()
    confirm_password_reset = ConfirmPasswordResetMutation.Field()
    
    initiate_mfa_setup = InitiateMFASetupMutation.Field(description="Initiates the MFA setup process for the authenticated user.")
    verify_mfa_setup = VerifyMFASetupMutation.Field(description="Verifies the OTP code and enables MFA for the user.")
    disable_mfa = DisableMFAMutation.Field(description="Disables MFA for the authenticated user after verification.")
    toggle_email_mfa = ToggleEmailMfaMutation.Field(description="Enables or disables Email as an MFA factor.")
    add_phone_number = AddPhoneNumberMutation.Field(description="Adds a phone number and sends a verification code.")
    verify_phone_number = VerifyPhoneNumberMutation.Field(description="Verifies the OTP sent to a phone number.")


# Build the federated schema
schema = build_schema(query=UserQuery, mutation=UserMutation, federation_version=LATEST_VERSION)
