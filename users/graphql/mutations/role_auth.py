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


class InitiatePatientAuthMutation(graphene.Mutation):
    """
    Initiate passwordless authentication for patients using email or phone.
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
        
        # Find or create patient user
        user = None
        if email:
            try:
                user = User.objects.get(email=email)
                if not user.is_patient():
                    # Auto-assign patient role if not already assigned
                    role_manager = RoleManager(user)
                    role_manager.assign_role('PATIENT', reason='Passwordless authentication')
            except User.DoesNotExist:
                # Create new patient user
                user = User.objects.create_user(
                    email=email,
                    is_passwordless=True,
                    email_verified=False
                )
                role_manager = RoleManager(user)
                role_manager.assign_role('PATIENT', reason='Auto-registration')
        
        elif phone_number:
            try:
                user = User.objects.get(phone_number=phone_number)
                if not user.is_patient():
                    role_manager = RoleManager(user)
                    role_manager.assign_role('PATIENT', reason='Passwordless authentication')
            except User.DoesNotExist:
                # Create new patient user with phone
                user = User.objects.create_user(
                    email=f"patient_{phone_number}@temp.local",  # Temporary email
                    phone_number=phone_number,
                    is_passwordless=True,
                    phone_number_verified=False
                )
                role_manager = RoleManager(user)
                role_manager.assign_role('PATIENT', reason='Auto-registration')
        
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
            if '@temp.local' not in user.email:
                user.email_verified = True
            if user.phone_number:
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
    Enhanced provider login with mandatory TOTP verification.
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


class AdminLoginMutation(graphene.Mutation):
    """
    Enhanced admin login with strict security requirements.
    """
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)
        totp_code = graphene.String(required=True)
        device_fingerprint = graphene.String(required=True)
        client_id = graphene.String()  # Optional when CLIENT_AUTH_ENABLED=false
        client_api_key = graphene.String()  # Optional when CLIENT_AUTH_ENABLED=false
    
    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)
    
    @classmethod
    @require_client_auth(['ADMIN_WEB'])
    @transaction.atomic
    def mutate(cls, root, info, email, password, totp_code, device_fingerprint):
        try:
            # Authenticate user
            user = authenticate(username=email, password=password)
            if not user:
                raise GraphQLError("Invalid credentials")
            
            # Verify user is admin
            if not user.is_admin_user():
                raise GraphQLError("User is not an administrator")
            
            # Verify TOTP (mandatory for admins)
            if not user.mfa_totp_setup_complete:
                raise GraphQLError("TOTP setup required for admin account")
            
            if not verify_otp(user, totp_code, 'totp'):
                raise GraphQLError("Invalid TOTP code")
            
            # Verify device fingerprint is provided
            if not device_fingerprint:
                raise GraphQLError("Device fingerprint required for admin authentication")
            
            # Create auth payload with shorter token lifetime
            client = get_client_from_context(info)
            
            auth_data = create_auth_payload(
                user,
                mfa_required=False,
                client=client,
                device_fingerprint=device_fingerprint
            )
            
            return AdminLoginMutation(
                auth_payload=AuthPayloadType(**auth_data)
            )
            
        except Exception as e:
            return AdminLoginMutation(
                errors=[str(e)]
            )


class AssignUserRoleMutation(graphene.Mutation):
    """
    Assign a role to a user (admin only).
    """
    class Arguments:
        user_id = graphene.String(required=True)
        role_name = graphene.String(required=True)
        reason = graphene.String()
        expires_at = graphene.DateTime()
    
    success = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)
    
    @classmethod
    @graphql_require_role('ADMIN')
    @transaction.atomic
    def mutate(cls, root, info, user_id, role_name, reason=None, expires_at=None):
        try:
            # Get target user
            try:
                target_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise GraphQLError("User not found")
            
            # Get current user (admin)
            current_user = info.context.user
            
            # Assign role
            role_manager = RoleManager(target_user, assigned_by=current_user)
            assignment = role_manager.assign_role(role_name, expires_at, reason)
            
            return AssignUserRoleMutation(
                success=True,
                message=f"Role '{role_name}' assigned to user {target_user.email}"
            )
            
        except Exception as e:
            return AssignUserRoleMutation(
                success=False,
                errors=[str(e)]
            )


class RemoveUserRoleMutation(graphene.Mutation):
    """
    Remove a role from a user (admin only).
    """
    class Arguments:
        user_id = graphene.String(required=True)
        role_name = graphene.String(required=True)
        reason = graphene.String()
    
    success = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)
    
    @classmethod
    @graphql_require_role('ADMIN')
    @transaction.atomic
    def mutate(cls, root, info, user_id, role_name, reason=None):
        try:
            # Get target user
            try:
                target_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise GraphQLError("User not found")
            
            # Get current user (admin)
            current_user = info.context.user
            
            # Remove role
            role_manager = RoleManager(target_user, assigned_by=current_user)
            success = role_manager.remove_role(role_name, reason)
            
            if success:
                return RemoveUserRoleMutation(
                    success=True,
                    message=f"Role '{role_name}' removed from user {target_user.email}"
                )
            else:
                return RemoveUserRoleMutation(
                    success=False,
                    errors=[f"User does not have role '{role_name}'"]
                )
            
        except Exception as e:
            return RemoveUserRoleMutation(
                success=False,
                errors=[str(e)]
            )
