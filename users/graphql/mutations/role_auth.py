import logging
import graphene
from django.db import transaction
from django.contrib.auth import authenticate
from graphql import GraphQLError

from ..types import AuthPayloadType
from ..services import create_auth_payload
from ..client_auth import require_client_auth, get_client_from_context
from ...models import User, UserRole
from ...role_management import RoleManager, RoleValidationService
from ...permissions import graphql_require_role, graphql_require_permission
from ...otp_utils import generate_otp, set_user_otp, verify_otp
from ...communication_client import send_templated_email, send_sms

logger = logging.getLogger(__name__)


class InitiatePatientAuthMutation(graphene.Mutation):
    """
    Initiate passwordless authentication for patients using email or phone.
    Handles both registration and login automatically with dual role support.
    """
    class Arguments:
        email = graphene.String()
        phone_number = graphene.String()
        client_id = graphene.String()  # Optional when CLIENT_AUTH_ENABLED=false
        client_api_key = graphene.String()  # Optional when CLIENT_AUTH_ENABLED=false
    
    success = graphene.Boolean()
    message = graphene.String()
    otp_token = graphene.String()
    
    @classmethod
    @require_client_auth(['PATIENT_WEB', 'PATIENT_MOBILE'])
    @transaction.atomic
    def mutate(cls, root, info, email=None, phone_number=None):
        if not email and not phone_number:
            raise GraphQLError("Either email or phone_number is required")
        
        client = get_client_from_context(info)
        
        # Find or create patient user with dual role support
        user = None
        is_new_user = False
        role_assigned = False
        
        if email:
            try:
                user = User.objects.get(email=email)
                logger.info(f"Found existing user {email} for patient authentication")
                
                # Check if user already has PATIENT role
                if not user.is_patient():
                    # User exists but doesn't have PATIENT role - add it (dual role scenario)
                    role_manager = RoleManager(user)
                    role_manager.assign_role('PATIENT', reason='Patient authentication - dual role assignment')
                    role_assigned = True
                    logger.info(f"Added PATIENT role to existing user {email} (dual role scenario)")
                else:
                    logger.info(f"User {email} already has PATIENT role")
                    
            except User.DoesNotExist:
                # Create new patient user
                user = User.objects.create_user(
                    email=email,
                    is_passwordless=True,
                    email_verified=False
                )
                role_manager = RoleManager(user)
                role_manager.assign_role('PATIENT', reason='Auto-registration via patient authentication')
                is_new_user = True
                role_assigned = True
                logger.info(f"Created new patient user {email}")
        
        elif phone_number:
            try:
                user = User.objects.get(phone_number=phone_number)
                logger.info(f"Found existing user with phone {phone_number} for patient authentication")
                
                if not user.is_patient():
                    # User exists but doesn't have PATIENT role - add it (dual role scenario)
                    role_manager = RoleManager(user)
                    role_manager.assign_role('PATIENT', reason='Patient authentication via phone - dual role assignment')
                    role_assigned = True
                    logger.info(f"Added PATIENT role to existing user with phone {phone_number} (dual role scenario)")
                else:
                    logger.info(f"User with phone {phone_number} already has PATIENT role")
                    
            except User.DoesNotExist:
                # Create new patient user with phone
                # Use phone number as unique identifier in email format for database constraints
                phone_email = f"{phone_number.replace('+', '').replace(' ', '')}@phone.afyaflow.local"
                user = User.objects.create_user(
                    email=phone_email,  # Phone-based email identifier
                    phone_number=phone_number,
                    is_passwordless=True,
                    phone_number_verified=False,
                    email_verified=False  # This is not a real email
                )
                role_manager = RoleManager(user)
                role_manager.assign_role('PATIENT', reason='Auto-registration via patient phone authentication')
                is_new_user = True
                role_assigned = True
                logger.info(f"Created new patient user with phone {phone_number}")
        
        # Generate OTP
        otp_code = generate_otp()
        set_user_otp(user, otp_code, purpose='patient_login')
        otp_token = f"patient_auth_{user.id}_{otp_code}"

        # Send OTP using your existing email service
        if email:
            try:
                send_templated_email(
                    recipient=email,
                    template_id='patient_login_otp',
                    context={
                        "first_name": user.first_name or "Patient",
                        "otp_code": otp_code
                    }
                )
                message = f"OTP sent to {email}"
            except Exception as e:
                logger.error(f"Failed to send patient login OTP to {email}: {e}")
                raise GraphQLError("Failed to send OTP. Please try again.")
        else:
            try:
                send_sms(
                    recipient=phone_number,
                    message=f"Your AfyaFlow verification code is: {otp_code}"
                )
                message = f"OTP sent to {phone_number}"
            except Exception as e:
                logger.error(f"Failed to send patient login SMS to {phone_number}: {e}")
                raise GraphQLError("Failed to send OTP. Please try again.")
        
        return InitiatePatientAuthMutation(
            success=True,
            message=message,
            otp_token=otp_token
        )


class CompletePatientAuthMutation(graphene.Mutation):
    """
    Complete passwordless authentication for patients by verifying OTP.
    """
    class Arguments:
        otp_token = graphene.String(required=True)
        otp_code = graphene.String(required=True)
        client_id = graphene.String()  # Optional when CLIENT_AUTH_ENABLED=false
        client_api_key = graphene.String()  # Optional when CLIENT_AUTH_ENABLED=false
    
    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)
    
    @classmethod
    @require_client_auth(['PATIENT_WEB', 'PATIENT_MOBILE'])
    @transaction.atomic
    def mutate(cls, root, info, otp_token, otp_code):
        try:
            # Parse OTP token
            if not otp_token.startswith('patient_auth_'):
                raise GraphQLError("Invalid OTP token")
            
            parts = otp_token.split('_')
            if len(parts) != 4:
                raise GraphQLError("Invalid OTP token format")
            
            user_id = parts[2]
            expected_otp = parts[3]
            
            # Verify OTP
            if otp_code != expected_otp:
                raise GraphQLError("Invalid OTP code")
            
            # Get user
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise GraphQLError("User not found")
            
            # Verify user is patient
            if not user.is_patient():
                raise GraphQLError("User is not a patient")
            
            # Mark email/phone as verified
            if '@phone.afyaflow.local' not in user.email:
                # This is a real email address, mark as verified
                user.email_verified = True
            if user.phone_number:
                # Mark phone as verified for phone-based authentication
                user.phone_number_verified = True
            user.save()
            
            # Create auth payload
            client = get_client_from_context(info)
            device_fingerprint = info.context.META.get('HTTP_X_DEVICE_FINGERPRINT')
            
            auth_data = create_auth_payload(
                user,
                mfa_required=False,
                client=client,
                device_fingerprint=device_fingerprint
            )
            
            return CompletePatientAuthMutation(
                auth_payload=AuthPayloadType(**auth_data)
            )
            
        except Exception as e:
            return CompletePatientAuthMutation(
                errors=[str(e)]
            )


class ProviderLoginMutation(graphene.Mutation):
    """
    Enhanced provider login with conditional TOTP verification.
    """
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)
        totp_code = graphene.String()
        client_id = graphene.String()  # Optional when CLIENT_AUTH_ENABLED=false
        client_api_key = graphene.String()  # Optional when CLIENT_AUTH_ENABLED=false
    
    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)
    
    @classmethod
    @require_client_auth(['PROVIDER_WEB', 'PROVIDER_MOBILE'])
    @transaction.atomic
    def mutate(cls, root, info, email, password, totp_code=None):
        try:
            # Authenticate user
            user = authenticate(username=email, password=password)
            if not user:
                raise GraphQLError("Invalid credentials")
            
            # Verify user is provider
            if not user.is_provider():
                raise GraphQLError("User is not a provider")
            
            # Check if TOTP is required and provided
            client = get_client_from_context(info)
            client_type = client.client_type if client else 'PROVIDER_WEB'
            if user.requires_totp_for_client(client_type):
                if not totp_code:
                    raise GraphQLError("TOTP code required for provider authentication")
                
                if not user.mfa_totp_setup_complete:
                    raise GraphQLError("TOTP setup required for provider account")
                
                # Verify TOTP code
                if not verify_otp(user, totp_code, 'totp'):
                    raise GraphQLError("Invalid TOTP code")
            
            # Create auth payload
            device_fingerprint = info.context.META.get('HTTP_X_DEVICE_FINGERPRINT')
            
            auth_data = create_auth_payload(
                user,
                mfa_required=False,
                client=client,
                device_fingerprint=device_fingerprint
            )
            
            return ProviderLoginMutation(
                auth_payload=AuthPayloadType(**auth_data)
            )
            
        except Exception as e:
            return ProviderLoginMutation(
                errors=[str(e)]
            )


# COMMENTED OUT: Admin features not needed for now
# AdminLoginMutation, AssignUserRoleMutation, and RemoveUserRoleMutation
# have been removed to simplify the authentication system.
        