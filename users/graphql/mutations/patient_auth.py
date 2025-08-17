import graphene
import logging
import re
from django.utils import timezone
from graphql import GraphQLError

from ..types import AuthPayloadType, PatientOTPResponse
from ...models import User, AuthenticationAttempt
from ...otp_utils import generate_otp, set_user_otp, verify_otp
from ...communication_client import send_templated_email, send_sms
from ..services import create_auth_payload
from ...security_middleware import auth_attempt_tracker

logger = logging.getLogger(__name__)


def get_client_ip(info):
    """Extract client IP from GraphQL context."""
    request = info.context
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'unknown')


def validate_identifier(identifier: str) -> tuple[str, str]:
    """
    Validate and determine the type of identifier (email or phone).
    
    Args:
        identifier: The email or phone number to validate
        
    Returns:
        Tuple of (identifier_type, normalized_identifier)
        
    Raises:
        GraphQLError: If identifier is invalid
    """
    identifier = identifier.strip()
    
    # Email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_pattern, identifier):
        return 'email', identifier.lower()
    
    # Phone validation (basic international format)
    phone_pattern = r'^\+?[1-9]\d{1,14}$'  # E.164 format
    if re.match(phone_pattern, identifier.replace(' ', '').replace('-', '')):
        # Normalize phone number
        normalized_phone = identifier.replace(' ', '').replace('-', '')
        if not normalized_phone.startswith('+'):
            # Assume US number if no country code
            normalized_phone = '+1' + normalized_phone
        return 'phone', normalized_phone
    
    raise GraphQLError("Invalid identifier. Please provide a valid email address or phone number.")


class InitiatePatientAuthMutation(graphene.Mutation):
    """
    Initiates passwordless authentication for patients by sending an OTP.
    Supports both email and phone number identifiers.
    """
    
    class Arguments:
        identifier = graphene.String(
            required=True, 
            description="Email address or phone number for the patient"
        )
    
    response = graphene.Field(PatientOTPResponse)
    
    @classmethod
    def mutate(cls, root, info, identifier):
        client_ip = get_client_ip(info)
        
        try:
            # Validate and determine identifier type
            identifier_type, normalized_identifier = validate_identifier(identifier)
            
            # Check if user exists
            if identifier_type == 'email':
                try:
                    user = User.objects.get(email=normalized_identifier)
                    existing_user = True
                except User.DoesNotExist:
                    user = None
                    existing_user = False
            else:  # phone
                try:
                    user = User.objects.get(phone_number=normalized_identifier)
                    existing_user = True
                except User.DoesNotExist:
                    user = None
                    existing_user = False
            
            # Check if user can access patient services
            if existing_user and not user.can_act_as_patient():
                # Only operations users are blocked from patient services
                if user.user_type == 'operations':
                    # Log attempt but don't reveal user type for security
                    AuthenticationAttempt.objects.create(
                        email=normalized_identifier if identifier_type == 'email' else None,
                        attempt_type='login',
                        ip_address=client_ip,
                        user_agent=info.context.META.get('HTTP_USER_AGENT', ''),
                        success=False,
                        failure_reason='Operations user attempted passwordless auth',
                        user=user,
                        metadata={'identifier_type': identifier_type}
                    )

                    return cls(response=PatientOTPResponse(
                        success=False,
                        message="This authentication method is not available for your account type.",
                        otp_sent=False
                    ))

                # For providers, auto-enable patient services
                elif user.user_type == 'provider':
                    user.enable_patient_services()
                    logger.info(f"Auto-enabled patient services for provider: {user.email}")
            
            # Generate OTP
            otp = generate_otp()
            
            # For existing users, save OTP to their record
            if existing_user:
                set_user_otp(user, otp, purpose='patient_auth')
                expires_at = user.mfa_otp_expires_at
            else:
                # For new users, we'll store the OTP temporarily in cache
                # This is handled in the complete mutation
                from django.core.cache import cache
                cache_key = f"patient_otp:{normalized_identifier}"
                expires_at = timezone.now() + timezone.timedelta(minutes=10)
                cache.set(cache_key, {
                    'otp': otp,
                    'expires_at': expires_at.isoformat(),
                    'identifier_type': identifier_type
                }, timeout=600)  # 10 minutes
            
            # Send OTP
            if identifier_type == 'email':
                success = send_templated_email(
                    recipient=normalized_identifier,
                    template_id='patient_auth_otp',
                    context={
                        'otp_code': otp,
                        'expires_minutes': 10
                    }
                )
            else:  # phone
                message = f"Your AfyaFlow verification code is: {otp}. Valid for 10 minutes."
                success = send_sms(recipient=normalized_identifier, message=message)
            
            if not success:
                logger.error(f"Failed to send OTP to {normalized_identifier} via {identifier_type}")
                return cls(response=PatientOTPResponse(
                    success=False,
                    message="Failed to send verification code. Please try again.",
                    otp_sent=False
                ))
            
            # Log successful OTP send
            AuthenticationAttempt.objects.create(
                email=normalized_identifier if identifier_type == 'email' else None,
                attempt_type='login',
                ip_address=client_ip,
                user_agent=info.context.META.get('HTTP_USER_AGENT', ''),
                success=True,
                user=user if existing_user else None,
                metadata={
                    'identifier_type': identifier_type,
                    'otp_sent': True,
                    'existing_user': existing_user
                }
            )
            
            logger.info(f"OTP sent to {normalized_identifier} via {identifier_type} for patient auth")
            
            return cls(response=PatientOTPResponse(
                success=True,
                message=f"Verification code sent to your {identifier_type}.",
                otp_sent=True,
                expires_at=expires_at,
                identifier_type=identifier_type
            ))
            
        except GraphQLError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error in patient auth initiation: {e}")
            
            # Log failed attempt
            AuthenticationAttempt.objects.create(
                email=identifier if '@' in identifier else None,
                attempt_type='login',
                ip_address=client_ip,
                user_agent=info.context.META.get('HTTP_USER_AGENT', ''),
                success=False,
                failure_reason=f'Unexpected error: {str(e)[:200]}',
                metadata={'identifier': identifier}
            )
            
            raise GraphQLError("An unexpected error occurred. Please try again.")


class CompletePatientAuthMutation(graphene.Mutation):
    """
    Completes passwordless authentication for patients by verifying the OTP.
    Auto-registers new patients and logs in existing ones.
    """
    
    class Arguments:
        identifier = graphene.String(
            required=True,
            description="Email address or phone number used in initiation"
        )
        otp = graphene.String(
            required=True,
            description="The OTP code received via email or SMS"
        )
        first_name = graphene.String(
            description="First name (required for new patient registration)"
        )
        last_name = graphene.String(
            description="Last name (required for new patient registration)"
        )
    
    auth_payload = graphene.Field(AuthPayloadType)
    errors = graphene.List(graphene.String)
    
    @classmethod
    def mutate(cls, root, info, identifier, otp, first_name=None, last_name=None):
        client_ip = get_client_ip(info)
        
        try:
            # Validate identifier
            identifier_type, normalized_identifier = validate_identifier(identifier)
            
            # Check if user exists
            if identifier_type == 'email':
                try:
                    user = User.objects.get(email=normalized_identifier)
                    existing_user = True
                except User.DoesNotExist:
                    user = None
                    existing_user = False
            else:  # phone
                try:
                    user = User.objects.get(phone_number=normalized_identifier)
                    existing_user = True
                except User.DoesNotExist:
                    user = None
                    existing_user = False
            
            # Verify OTP
            if existing_user:
                # Verify OTP from user record
                if not verify_otp(otp, user, purpose='patient_auth'):
                    AuthenticationAttempt.objects.create(
                        email=normalized_identifier if identifier_type == 'email' else None,
                        attempt_type='login',
                        ip_address=client_ip,
                        user_agent=info.context.META.get('HTTP_USER_AGENT', ''),
                        success=False,
                        failure_reason='Invalid or expired OTP',
                        user=user,
                        metadata={'identifier_type': identifier_type}
                    )
                    return cls(auth_payload=None, errors=["Invalid or expired verification code."])
            else:
                # Verify OTP from cache for new users
                from django.core.cache import cache
                cache_key = f"patient_otp:{normalized_identifier}"
                cached_data = cache.get(cache_key)
                
                if not cached_data or cached_data['otp'] != otp:
                    AuthenticationAttempt.objects.create(
                        email=normalized_identifier if identifier_type == 'email' else None,
                        attempt_type='registration',
                        ip_address=client_ip,
                        user_agent=info.context.META.get('HTTP_USER_AGENT', ''),
                        success=False,
                        failure_reason='Invalid or expired OTP for new user',
                        metadata={'identifier_type': identifier_type}
                    )
                    return cls(auth_payload=None, errors=["Invalid or expired verification code."])
                
                # Check if OTP is expired
                expires_at = timezone.datetime.fromisoformat(cached_data['expires_at'])
                if timezone.now() > expires_at:
                    cache.delete(cache_key)
                    return cls(auth_payload=None, errors=["Verification code has expired."])
                
                # Create new patient user
                user_data = {
                    'first_name': first_name.strip() if first_name else '',
                    'last_name': last_name.strip() if last_name else '',
                    'user_type': 'patient',
                    'is_active': True
                }
                
                if identifier_type == 'email':
                    user_data['email'] = normalized_identifier
                    user_data['email_verified'] = True  # Email verified via OTP
                else:  # phone
                    # For phone-only registration, generate a smart placeholder email
                    normalized_phone = normalized_identifier.replace('+', '').replace('-', '')
                    user_data['email'] = f"phone.{normalized_phone}@afyaflow.app"
                    user_data['phone_number'] = normalized_identifier
                    user_data['phone_number_verified'] = True
                
                user = User.objects.create_user(**user_data)
                
                # Clear the cache
                cache.delete(cache_key)
                
                logger.info(f"Created new patient user: {user.email}")
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Create auth payload with patient context
            # For providers using patient services, set current_context to 'patient'
            current_context = 'patient' if user.user_type == 'provider' else None
            auth_payload = create_auth_payload(user, mfa_required=False, current_context=current_context)
            
            # Log successful authentication
            AuthenticationAttempt.objects.create(
                email=user.email,
                attempt_type='login' if existing_user else 'registration',
                ip_address=client_ip,
                user_agent=info.context.META.get('HTTP_USER_AGENT', ''),
                success=True,
                user=user,
                metadata={
                    'identifier_type': identifier_type,
                    'existing_user': existing_user,
                    'passwordless': True
                }
            )
            
            logger.info(f"Patient authentication successful for {user.email}")
            
            return cls(auth_payload=auth_payload, errors=None)
            
        except GraphQLError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error in patient auth completion: {e}")
            
            # Log failed attempt
            AuthenticationAttempt.objects.create(
                email=identifier if '@' in identifier else None,
                attempt_type='login',
                ip_address=client_ip,
                user_agent=info.context.META.get('HTTP_USER_AGENT', ''),
                success=False,
                failure_reason=f'Unexpected error: {str(e)[:200]}',
                metadata={'identifier': identifier}
            )
            
            return cls(auth_payload=None, errors=["An unexpected error occurred. Please try again."])
