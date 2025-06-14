import graphene
import pyotp
import logging
from django.db import transaction

from ..types import UserType

logger = logging.getLogger(__name__)

class InitiateMFASetupMutation(graphene.Mutation):
    """Initiates the MFA setup process for the authenticated user."""
    otp_provisioning_uri = graphene.String()
    mfa_secret = graphene.String()
    ok = graphene.Boolean()
    errors = graphene.List(graphene.String)

    @classmethod
    @transaction.atomic
    def mutate(cls, root, info):
        user = info.context.user
        if user.is_anonymous:
            return InitiateMFASetupMutation(ok=False, errors=["User is not authenticated."])

        if user.mfa_enabled and user.mfa_setup_complete:
            return InitiateMFASetupMutation(ok=False, errors=["MFA is already set up. Disable it first to re-setup."])

        temp_secret = pyotp.random_base32()
        user.mfa_secret = temp_secret
        user.mfa_enabled = False
        user.mfa_setup_complete = False
        user.save(update_fields=['mfa_secret', 'mfa_enabled', 'mfa_setup_complete'])

        issuer_name = "Afyaflow"  # Consider making this a setting
        otp_uri = pyotp.totp.TOTP(temp_secret).provisioning_uri(
            name=user.email,
            issuer_name=issuer_name
        )
        
        logger.info(f"MFA setup initiated for user {user.email}.")
        return InitiateMFASetupMutation(
            ok=True,
            otp_provisioning_uri=otp_uri,
            mfa_secret=temp_secret
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
            user.mfa_enabled = True
            user.mfa_setup_complete = True
            user.save(update_fields=['mfa_enabled', 'mfa_setup_complete'])
            logger.info(f"MFA setup verified for user {user.email}.")
            return VerifyMFASetupMutation(ok=True, user=user)
        else:
            logger.warning(f"MFA verification failed for user {user.email}: Invalid OTP code.")
            return VerifyMFASetupMutation(ok=False, user=user, errors=["Invalid OTP code."])

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
            return DisableMFAMutation(ok=False, user=user, errors=["Invalid OTP code."])

        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_setup_complete = False
        user.save(update_fields=['mfa_enabled', 'mfa_secret', 'mfa_setup_complete'])
        logger.info(f"MFA disabled for user {user.email}.")
        return DisableMFAMutation(ok=True, user=user)
