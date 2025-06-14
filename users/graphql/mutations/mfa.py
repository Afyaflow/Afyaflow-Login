import graphene
import pyotp
import qrcode
from io import BytesIO
import base64
from graphql import GraphQLError
from ...communication_client import send_templated_email
import logging
from django.db import transaction

from ..types import UserType

logger = logging.getLogger(__name__)

class InitiateMFASetupMutation(graphene.Mutation):
    """Initiates the MFA setup process for the authenticated user."""
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

        if user.mfa_setup_complete:
            return cls(ok=False, errors=["MFA is already set up and verified."])

        # Generate a new secret
        temp_secret = pyotp.random_base32()
        user.mfa_secret = temp_secret
        user.mfa_setup_complete = False
        user.save(update_fields=['mfa_secret', 'mfa_setup_complete'])

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

class VerifyMFASetupMutation(graphene.Mutation):
    """Verifies the OTP code and enables MFA for the user."""
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
            return VerifyMFASetupMutation(ok=False, errors=["User is not authenticated."])

        if not user.mfa_secret:
            return VerifyMFASetupMutation(ok=False, errors=["MFA setup has not been initiated."])
        
        if user.mfa_setup_complete:
            return VerifyMFASetupMutation(ok=False, errors=["MFA is already verified."])

        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(otp_code):
            user.mfa_setup_complete = True
            user.mfa_enabled = True
            user.save(update_fields=['mfa_enabled', 'mfa_setup_complete'])

            logger.info(f"MFA setup was successfully verified for user {user.email}")
            return VerifyMFASetupMutation(ok=True)
        else:
            logger.warning(f"MFA verification failed for user {user.email}: Invalid OTP code.")
            return VerifyMFASetupMutation(ok=False, errors=["Invalid OTP code."])

class DisableMFAMutation(graphene.Mutation):
    """Disables MFA for the authenticated user."""
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
            return DisableMFAMutation(ok=False, errors=["User is not authenticated."])

        if not user.mfa_setup_complete:
            return DisableMFAMutation(ok=False, errors=["MFA is not enabled."])
        
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(otp_code):
            logger.warning(f"MFA disable failed for user {user.email}: Invalid OTP code.")
            return DisableMFAMutation(ok=False, errors=["Invalid OTP code."])

        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_setup_complete = False
        user.save(update_fields=['mfa_enabled', 'mfa_secret', 'mfa_setup_complete'])

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
        return DisableMFAMutation(ok=True, errors=None)
