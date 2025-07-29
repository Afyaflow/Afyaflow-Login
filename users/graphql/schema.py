import graphene
from graphene_federation import LATEST_VERSION, build_schema

# Import mutations first
from .mutations.auth import (
    RegisterMutation,
    LoginMutation,
    VerifyMfaMutation,
    RefreshTokenMutation,
    LogoutMutation,
    GetScopedAccessToken,
)
from .mutations.social_auth import (
    GoogleLoginMutation,
    MicrosoftLoginMutation,
    LinkedInLoginMutation,
)
from .mutations.profile import (
    UpdateProfileMutation,
    ChangePasswordMutation,
    InitiatePasswordResetMutation,
    ResetPasswordWithOtpMutation,
)
from .mutations.mfa import (
    InitiateTotpSetupMutation,
    VerifyTotpSetupMutation,
    DisableTotpMutation,
    InitiateEmailMfaSetupMutation,
    VerifyEmailMfaSetupMutation,
    DisableEmailMfaMutation,
    InitiateSmsMfaSetupMutation,
    VerifySmsMfaSetupMutation,
    DisableSmsMfaMutation,
    AddPhoneNumberMutation,
    VerifyPhoneNumberMutation,
    UpdatePhoneNumberMutation,
    RemovePhoneNumberMutation,
    ResendPhoneVerificationMutation,
)
from .mutations.verification import (
    VerifyEmailMutation,
    ResendVerificationEmailMutation,
)
from .mutations.patient_auth import (
    InitiatePatientAuthMutation,
    CompletePatientAuthMutation,
)
from .mutations.email_update import (
    AddEmailMutation,
    VerifyAddEmailMutation,
)

# Then import queries
from .queries import UserQuery


class UserMutation(graphene.ObjectType):
    """Root mutation for user-related actions."""
    register = RegisterMutation.Field()
    login = LoginMutation.Field()
    verify_mfa = VerifyMfaMutation.Field(description="Completes the second step of an MFA login.")
    refresh_token = RefreshTokenMutation.Field()
    logout = LogoutMutation.Field()
    get_scoped_access_token = GetScopedAccessToken.Field(description="Issues an Organization Context Token (OCT) for a specific organization.")
    
    # Social Auth
    login_with_google = GoogleLoginMutation.Field(description="Login with Google OAuth2")
    login_with_microsoft = MicrosoftLoginMutation.Field(description="Login with Microsoft OAuth2")
    login_with_linkedin = LinkedInLoginMutation.Field(description="Login with LinkedIn OAuth2")
    
    update_profile = UpdateProfileMutation.Field()
    change_password = ChangePasswordMutation.Field()
    initiate_password_reset = InitiatePasswordResetMutation.Field()
    reset_password_with_otp = ResetPasswordWithOtpMutation.Field()
    
    # Email Verification
    verify_email = VerifyEmailMutation.Field()
    resend_verification_email = ResendVerificationEmailMutation.Field()

    # MFA Management
    # TOTP
    initiate_totp_setup = InitiateTotpSetupMutation.Field()
    verify_totp_setup = VerifyTotpSetupMutation.Field()
    disable_totp = DisableTotpMutation.Field()
    
    # Email MFA
    initiate_email_mfa_setup = InitiateEmailMfaSetupMutation.Field()
    verify_email_mfa_setup = VerifyEmailMfaSetupMutation.Field()
    disable_email_mfa = DisableEmailMfaMutation.Field()

    # SMS MFA
    initiate_sms_mfa_setup = InitiateSmsMfaSetupMutation.Field()
    verify_sms_mfa_setup = VerifySmsMfaSetupMutation.Field()
    disable_sms_mfa = DisableSmsMfaMutation.Field()

    # Phone Management
    add_phone_number = AddPhoneNumberMutation.Field(description="Adds a phone number and sends a verification code.")
    verify_phone_number = VerifyPhoneNumberMutation.Field(description="Verifies the OTP sent to a phone number.")
    update_phone_number = UpdatePhoneNumberMutation.Field(description="Updates the user's phone number and sends a verification code.")
    remove_phone_number = RemovePhoneNumberMutation.Field(description="Removes the user's phone number and disables SMS MFA.")
    resend_phone_verification = ResendPhoneVerificationMutation.Field(description="Resends the phone verification OTP.")

    # Patient Passwordless Authentication
    initiate_patient_auth = InitiatePatientAuthMutation.Field(description="Initiates passwordless authentication for patients by sending an OTP.")
    complete_patient_auth = CompletePatientAuthMutation.Field(description="Completes passwordless authentication for patients by verifying the OTP.")

    # Email Management (Phone-only users)
    add_email = AddEmailMutation.Field(description="Add real email address for phone-only users.")
    verify_add_email = VerifyAddEmailMutation.Field(description="Verify OTP and complete email addition for phone-only users.")


# Build the federated schema
schema = build_schema(query=UserQuery, mutation=UserMutation, federation_version=LATEST_VERSION)
