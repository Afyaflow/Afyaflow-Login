import graphene
import pyotp
import qrcode
from io import BytesIO
import base64
from graphql import GraphQLError
from ...communication_client import send_templated_email, send_sms
from ...otp_utils import generate_otp, verify_otp, hash_otp, set_user_otp
from ...models import User
import logging
from django.db import transaction
from django.utils import timezone
from datetime import timedelta

from ..types import UserType

logger = logging.getLogger(__name__)

# Helper function to check password
def _check_user_password(user, password):
    if not user.check_password(password):
        logger.warning(f"Password verification failed for user {user.email}.")
        raise GraphQLError("Invalid password.")

# --- TOTP (Authenticator App) Mutations ---

class InitiateTotpSetupMutation(graphene.Mutation):
    """Initiates the TOTP MFA setup process."""
    class Arguments:
        pass

    ok = graphene.Boolean()
    otp_provisioning_uri = graphene.String(description="The TOTP provisioning URI, for manual entry.")
    mfa_secret = graphene.String(description="The generated secret key for manual entry.")
    qr_code_image = graphene.String(description="A Base64-encoded PNG image of the QR code for MFA setup.")
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in to set up MFA.")

        if user.mfa_totp_setup_complete:
            return cls(ok=False, errors=["TOTP MFA is already set up and verified."])

        # Generate a new secret and mark setup as incomplete until verified.
        temp_secret = pyotp.random_base32()
        user.mfa_totp_secret = temp_secret
        user.mfa_totp_setup_complete = False # Explicitly mark as not complete
        user.save(update_fields=['mfa_totp_secret', 'mfa_totp_setup_complete'])

        # Generate provisioning URI
        issuer_name = "AfyaFlow"
        otp_uri = pyotp.totp.TOTP(temp_secret).provisioning_uri(
            name=user.email,
            issuer_name=issuer_name
        )

        # Generate QR code
        qr_image = qrcode.make(otp_uri)
        buffer = BytesIO()
        qr_image.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        # Send a notification email
        try:
            context = {"first_name": user.first_name or "user"}
            email_sent = send_templated_email(
                recipient=user.email,
                template_id='mfa_setup_initiated',
                context=context
            )
            if not email_sent:
                logger.warning(f"Failed to send MFA setup notification to {user.email}.")
        except Exception as e:
            logger.error(f"An unexpected error occurred trying to send MFA setup email for {user.email}: {e}")

        logger.info(f"MFA setup initiated for user {user.email}.")
        return cls(
            ok=True,
            otp_provisioning_uri=otp_uri,
            mfa_secret=temp_secret,
            qr_code_image=f"data:image/png;base64,{qr_code_base64}"
        )

class VerifyTotpSetupMutation(graphene.Mutation):
    """Verifies the TOTP code and completes the setup."""
    class Arguments:
        otp_code = graphene.String(required=True)

    ok = graphene.Boolean()
    user = graphene.Field(UserType)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, otp_code):
        user = info.context.user
        if user.is_anonymous:
            return VerifyTotpSetupMutation(ok=False, errors=["User is not authenticated."])

        if not user.mfa_totp_secret:
            return VerifyTotpSetupMutation(ok=False, errors=["MFA setup has not been initiated."])
        
        if user.mfa_totp_setup_complete:
            return VerifyTotpSetupMutation(ok=False, errors=["MFA is already verified."])

        totp = pyotp.TOTP(user.mfa_totp_secret)
        if totp.verify(otp_code):
            user.mfa_totp_setup_complete = True
            user.save(update_fields=['mfa_totp_setup_complete'])

            logger.info(f"TOTP MFA setup was successfully verified for user {user.email}")
            return VerifyTotpSetupMutation(ok=True)
        else:
            logger.warning(f"MFA verification failed for user {user.email}: Invalid OTP code.")
            return VerifyTotpSetupMutation(ok=False, errors=["Invalid OTP code."])

class DisableTotpMutation(graphene.Mutation):
    """Disables TOTP MFA for the user, requiring a valid TOTP code."""
    class Arguments:
        otp_code = graphene.String(required=True)

    ok = graphene.Boolean()
    user = graphene.Field(UserType)
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, otp_code):
        user = info.context.user
        if user.is_anonymous:
            return DisableTotpMutation(ok=False, errors=["User is not authenticated."])

        if not user.mfa_totp_secret:
            return DisableTotpMutation(ok=False, errors=["MFA setup has not been initiated."])
        
        if not user.mfa_totp_setup_complete:
            return DisableTotpMutation(ok=False, errors=["MFA is not enabled."])

        totp = pyotp.TOTP(user.mfa_totp_secret)
        if not totp.verify(otp_code):
            logger.warning(f"MFA disable failed for user {user.email}: Invalid OTP code.")
            return DisableTotpMutation(ok=False, errors=["Invalid OTP code."])

        # This mutation disables the entire TOTP method.
        user.mfa_totp_secret = None
        user.mfa_totp_setup_complete = False
        user.save(update_fields=['mfa_totp_secret', 'mfa_totp_setup_complete'])

        # Send confirmation email
        try:
            context = {"first_name": user.first_name or "user"}
            send_templated_email(
                recipient=user.email,
                template_id='mfa_disabled',
                context=context
            )
        except Exception as e:
            logger.error(f"Failed to send MFA disabling email for {user.email}: {e}")

        logger.info(f"MFA disabled for user {user.email}")
        return DisableTotpMutation(ok=True, errors=None)

# --- Email MFA Mutations ---

class InitiateEmailMfaSetupMutation(graphene.Mutation):
    """Sends a verification code to the user's email to start MFA setup."""
    class Arguments:
        pass

    ok = graphene.Boolean()
    message = graphene.String()

    @classmethod
    def mutate(cls, root, info):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in.")
        if user.mfa_email_enabled:
            raise GraphQLError("Email MFA is already enabled.")

        otp = generate_otp()
        set_user_otp(user, otp, purpose='mfa_setup') # Using purpose to distinguish OTPs

        try:
            send_templated_email(
                recipient=user.email,
                template_id='mfa_setup_otp',
                context={"first_name": user.first_name or "user", "otp_code": otp}
            )
            logger.info(f"Email MFA setup OTP sent to {user.email}.")
            return cls(ok=True, message="A verification code has been sent to your email.")
        except Exception as e:
            logger.error(f"Failed to send email MFA setup OTP to {user.email}: {e}")
            raise GraphQLError("Failed to send verification email.")

class VerifyEmailMfaSetupMutation(graphene.Mutation):
    """Verifies the code and enables Email MFA."""
    class Arguments:
        otp_code = graphene.String(required=True)

    ok = graphene.Boolean()

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, otp_code):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in.")

        if not verify_otp(otp_code, user, purpose='mfa_setup'):
            raise GraphQLError("Invalid or expired OTP code.")
        
        user.mfa_email_enabled = True
        user.mfa_otp = None
        user.mfa_otp_expires_at = None
        user.save()
        
        logger.info(f"Email MFA successfully enabled for user {user.email}.")
        return cls(ok=True)

class DisableEmailMfaMutation(graphene.Mutation):
    """Disables Email MFA after verifying the user's password."""
    class Arguments:
        password = graphene.String(required=True)
    
    ok = graphene.Boolean()

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, password):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in.")
        
        _check_user_password(user, password)
        
        user.mfa_email_enabled = False
        user.save(update_fields=['mfa_email_enabled'])
        logger.info(f"Email MFA disabled for user {user.email}.")
        return cls(ok=True)

# --- SMS MFA Mutations ---

class InitiateSmsMfaSetupMutation(graphene.Mutation):
    """Sends a verification code to the user's phone to start MFA setup."""
    class Arguments:
        pass

    ok = graphene.Boolean()
    message = graphene.String()

    @classmethod
    def mutate(cls, root, info):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in.")
        if not user.phone_number_verified:
            raise GraphQLError("You must have a verified phone number to enable SMS MFA.")
        if user.mfa_sms_enabled:
            raise GraphQLError("SMS MFA is already enabled.")

        otp = generate_otp()
        set_user_otp(user, otp, purpose='mfa_setup')

        try:
            message = f"Your AfyaFlow verification code is: {otp}"
            send_sms(recipient=user.phone_number, message=message)
            logger.info(f"SMS MFA setup OTP sent to phone number for user {user.email}.")
            return cls(ok=True, message="A verification code has been sent to your phone.")
        except Exception as e:
            logger.error(f"Failed to send SMS MFA setup OTP for user {user.email}: {e}")
            raise GraphQLError("Failed to send verification SMS.")

class VerifySmsMfaSetupMutation(graphene.Mutation):
    """Verifies the code and enables SMS MFA."""
    class Arguments:
        otp_code = graphene.String(required=True)

    ok = graphene.Boolean()

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, otp_code):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in.")

        if not verify_otp(otp_code, user, purpose='mfa_setup'):
            raise GraphQLError("Invalid or expired OTP code.")
        
        user.mfa_sms_enabled = True
        user.mfa_otp = None
        user.mfa_otp_expires_at = None
        user.save()
        
        logger.info(f"SMS MFA successfully enabled for user {user.email}.")
        return cls(ok=True)

class DisableSmsMfaMutation(graphene.Mutation):
    """Disables SMS MFA after verifying the user's password."""
    class Arguments:
        password = graphene.String(required=True)
    
    ok = graphene.Boolean()

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info, password):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in.")
        
        _check_user_password(user, password)
        
        user.mfa_sms_enabled = False
        user.save(update_fields=['mfa_sms_enabled'])
        logger.info(f"SMS MFA disabled for user {user.email}.")
        return cls(ok=True)

# --- Phone Number Management (remains the same) ---

class AddPhoneNumberMutation(graphene.Mutation):
    """Adds a phone number to a user's account and sends a verification OTP."""
    class Arguments:
        phone_number = graphene.String(required=True)

    ok = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, phone_number):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in to add a phone number.")

        # Basic validation can be improved with a library like phonenumbers
        if not phone_number or not phone_number.startswith('+'):
            return cls(ok=False, errors=["Invalid phone number format. Please use E.164 format (e.g., +12125552368)."])

        # Check if another user already has this number verified
        if User.objects.filter(phone_number=phone_number, phone_number_verified=True).exclude(pk=user.pk).exists():
            return cls(ok=False, errors=["This phone number is already in use."])

        user.phone_number = phone_number
        user.phone_number_verified = False  # Mark as unverified until OTP is confirmed
        
        otp = generate_otp()
        set_user_otp(user, otp, purpose='phone_verification')
        user.save(update_fields=['phone_number', 'phone_number_verified'])

        # Send the OTP via SMS
        message = f"Your AfyaFlow verification code is: {otp}"
        sms_sent = send_sms(recipient=phone_number, message=message)

        if not sms_sent:
            logger.error(f"Failed to send SMS OTP to {phone_number} for user {user.email}.")
            return cls(ok=False, errors=["Failed to send verification SMS. Please try again later."])

        logger.info(f"Verification OTP sent to {phone_number} for user {user.email}.")
        return cls(ok=True, message="A verification code has been sent to your phone.")

class VerifyPhoneNumberMutation(graphene.Mutation):
    """Verifies the OTP sent to a user's phone number."""
    class Arguments:
        otp_code = graphene.String(required=True)

    ok = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, otp_code):
        user = info.context.user
        if not user.is_authenticated:
            raise GraphQLError("You must be logged in to verify a phone number.")

        if not user.mfa_otp or not user.mfa_otp_expires_at:
            return cls(ok=False, errors=["No OTP verification is currently pending."])
        
        if timezone.now() > user.mfa_otp_expires_at:
            return cls(ok=False, errors=["The OTP code has expired."])

        if not verify_otp(otp_code, user, purpose='phone_verification'):
            return cls(ok=False, errors=["Invalid OTP code."])

        # Mark phone as verified and clear the temporary OTP
        user.phone_number_verified = True
        user.mfa_otp = None
        user.mfa_otp_expires_at = None
        user.save(update_fields=['phone_number_verified', 'mfa_otp', 'mfa_otp_expires_at'])

        logger.info(f"Phone number successfully verified for user {user.email}.")
        return cls(ok=True)
