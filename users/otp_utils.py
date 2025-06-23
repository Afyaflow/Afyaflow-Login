from django.utils import timezone
from datetime import timedelta
import random
from django.contrib.auth.hashers import make_password, check_password

def generate_otp(length: int = 6) -> str:
    """Generates a simple numeric OTP."""
    return "".join(str(random.randint(0, 9)) for _ in range(length))

def hash_otp(otp: str) -> str:
    """Hashes the OTP before saving."""
    return make_password(otp)

def verify_otp(provided_otp: str, user, purpose=None) -> bool:
    """
    Verifies a provided OTP against the one stored for the user,
    checking for expiry and matching purpose.
    """
    if not all([provided_otp, user, user.mfa_otp, user.mfa_otp_expires_at]):
        return False
    
    # Check if OTP is expired
    if timezone.now() > user.mfa_otp_expires_at:
        return False
        
    # Check if the purpose matches, if one is provided
    if purpose and user.mfa_otp_purpose != purpose:
        return False

    return check_password(provided_otp, user.mfa_otp)

def set_user_otp(user, otp: str, purpose=None):
    """Hashes and saves an OTP, its expiry, and its purpose to the user model."""
    user.mfa_otp = hash_otp(otp)
    user.mfa_otp_expires_at = timezone.now() + timedelta(minutes=10)
    user.mfa_otp_purpose = purpose
    user.save(update_fields=['mfa_otp', 'mfa_otp_expires_at', 'mfa_otp_purpose']) 