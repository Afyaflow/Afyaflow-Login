import graphene
import pyotp
import qrcode
import base64
from io import BytesIO
import logging
from graphql import GraphQLError
from ..types import MFASetupResponseType
from ...models import User
from ..services import send_templated_email

logger = logging.getLogger(__name__)

class InitiateMFASetupMutation(graphene.Mutation):
    """
    Initiates the MFA setup process for the authenticated user.
    Generates a new MFA secret and a QR code for authenticator apps.
    """
    class Arguments:
        pass

    response = graphene.Field(MFASetupResponseType)
    errors = graphene.List(graphene.String)

    @staticmethod
    def mutate(root, info):
        user = info.context.user
        if not user.is_authenticated:
            return InitiateMFASetupMutation(errors=["Authentication required."])

        # Generate a new secret for the user
        mfa_secret = pyotp.random_base32()
        user.mfa_secret = mfa_secret
        user.mfa_setup_complete = False  # Mark as incomplete until verified
        user.save()

        # Generate OTP provisioning URI
        otp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
            name=user.email,
            issuer_name="AfyaFlow"
        )

        # Generate QR code
        img = qrcode.make(otp_uri)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        logger.info(f"MFA setup initiated for user {user.email}.")
        return InitiateMFASetupMutation(
            response=MFASetupResponseType(qr_code_image=qr_code_base64, mfa_secret=mfa_secret),
            errors=None
        )

class VerifyMFASetupMutation(graphene.Mutation):
    """
    Verifies the OTP code to complete the MFA setup process.
    """
    class Arguments:
        mfa_code = graphene.String(required=True)

    success = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @staticmethod
    def mutate(root, info, mfa_code):
        user = info.context.user
        if not user.is_authenticated:
            return VerifyMFASetupMutation(success=False, errors=["Authentication required."])

        if not user.mfa_secret:
            return VerifyMFASetupMutation(success=False, errors=["MFA setup has not been initiated."])

        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(mfa_code):
            return VerifyMFASetupMutation(success=False, errors=["Invalid MFA code."])

        user.mfa_enabled = True
        user.mfa_setup_complete = True
        user.save()

        send_templated_email(
            recipient=user.email,
            template_id="mfa-enabled",
            context={"name": user.get_full_name()}
        )
        
        logger.info(f"MFA has been enabled for user {user.email}.")
        return VerifyMFASetupMutation(success=True, errors=None)

class DisableMFAMutation(graphene.Mutation):
    """
    Disables MFA for the authenticated user after verifying their password.
    """
    class Arguments:
        password = graphene.String(required=True)

    success = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @staticmethod
    def mutate(root, info, password):
        user = info.context.user
        if not user.is_authenticated:
            return DisableMFAMutation(success=False, errors=["Authentication required."])

        if not user.check_password(password):
            return DisableMFAMutation(success=False, errors=["Invalid password."])

        user.mfa_enabled = False
        user.mfa_setup_complete = False
        user.mfa_secret = None
        user.save()

        send_templated_email(
            recipient=user.email,
            template_id="mfa-disabled",
            context={"name": user.get_full_name()}
        )

        logger.info(f"MFA has been disabled for user {user.email}.")
        return DisableMFAMutation(success=True, errors=None)
