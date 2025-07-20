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
from .mutations.role_auth import (
    InitiatePatientAuthMutation,
    CompletePatientAuthMutation,
    ProviderLoginMutation,
    OperationsLoginMutation,
    # AdminLoginMutation, AssignUserRoleMutation, RemoveUserRoleMutation - commented out
)
from .mutations.operations import (
    CreateOperationsUserMutation,
    CreateServiceAccountMutation,
    UpdateServiceAccountMutation,
    DeleteServiceAccountMutation,
    LoadServiceAccountsFromEnvironmentMutation,
)
from .mutations.oct import (
    CreateOrganizationContextMutation,
    GetOrganizationContextTokenMutation,
    UpdateOrganizationContextMutation,
    ValidateTokensMutation,
)
from .mutations.service_auth import (
    GenerateServiceTokenMutation,
    ValidateServiceTokenMutation,
    CreateServiceToServiceTokenMutation,
    ReloadServiceAccountsMutation,
    GetServiceLoadStatusMutation,
    RegisterServiceMutation,
    ServiceHeartbeatMutation,
    UnregisterServiceMutation,
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

    # Enhanced Role-Based Authentication
    initiate_patient_auth = InitiatePatientAuthMutation.Field(description="Initiate passwordless authentication for patients")
    complete_patient_auth = CompletePatientAuthMutation.Field(description="Complete passwordless authentication for patients with OTP")
    provider_login = ProviderLoginMutation.Field(description="Enhanced provider login with conditional TOTP")
    operations_login = OperationsLoginMutation.Field(description="Operations user login for system administration")
    # admin_login, assign_user_role, remove_user_role - commented out for now

    # OPERATIONS User and Service Account Management
    create_operations_user = CreateOperationsUserMutation.Field(description="Create a new OPERATIONS user with system-wide privileges")
    create_service_account = CreateServiceAccountMutation.Field(description="Create a new service account for inter-service authentication")
    update_service_account = UpdateServiceAccountMutation.Field(description="Update an existing service account")
    delete_service_account = DeleteServiceAccountMutation.Field(description="Delete a service account")
    load_service_accounts_from_environment = LoadServiceAccountsFromEnvironmentMutation.Field(description="Load service accounts from environment variables")

    # Organization Context Token (OCT) Management
    create_organization_context = CreateOrganizationContextMutation.Field(description="Create a new organization context for OCT generation")
    get_organization_context_token = GetOrganizationContextTokenMutation.Field(description="Generate an Organization Context Token (OCT) for a provider")
    update_organization_context = UpdateOrganizationContextMutation.Field(description="Update an existing organization context")
    validate_tokens = ValidateTokensMutation.Field(description="Validate auth token and OCT for testing purposes")

    # Service Authentication and Token Management
    generate_service_token = GenerateServiceTokenMutation.Field(description="Generate a service authentication token")
    validate_service_token = ValidateServiceTokenMutation.Field(description="Validate a service authentication token")
    create_service_to_service_token = CreateServiceToServiceTokenMutation.Field(description="Create a token for service-to-service communication")
    reload_service_accounts = ReloadServiceAccountsMutation.Field(description="Reload service accounts from environment variables")
    get_service_load_status = GetServiceLoadStatusMutation.Field(description="Get current service account load status")

    # Service Discovery and Registry
    register_service = RegisterServiceMutation.Field(description="Register a service in the service registry")
    service_heartbeat = ServiceHeartbeatMutation.Field(description="Send a heartbeat from a service")
    unregister_service = UnregisterServiceMutation.Field(description="Unregister a service from the registry")


# Build the federated schema
schema = build_schema(query=UserQuery, mutation=UserMutation, federation_version=LATEST_VERSION)
