from django.utils import timezone
from datetime import timedelta
import random
from django.contrib.auth.hashers import make_password, check_password

def generate_otp(length: int = 6) -> str:
    """Generates a simple numeric OTP."""
    return "".join(str(random.randint(0, 9)) for _ in range(length))

def hash_otp(otp: str) -> str:
    """
    Hashes the OTP using Django's secure password hashing system.
    """
    # Using Django's built-in hasher. It's secure and handles salting automatically.
    return make_password(otp)

def verify_otp(provided_otp: str, hashed_otp: str) -> bool:
    """
    Verifies a provided OTP against its stored Django hash.
    """
    if not provided_otp or not hashed_otp:
        return False
    try:
        # check_password handles the verification securely.
        return check_password(provided_otp, hashed_otp)
    except Exception:
        # Handle cases where the hash format is invalid
        return False

def set_user_otp(user, otp_value: str, expiry_minutes: int = 10):
    """Generates an OTP, saves its hash and expiry to the user model."""
    user.mfa_otp = hash_otp(otp_value)
    user.mfa_otp_expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
    user.save(update_fields=['mfa_otp', 'mfa_otp_expires_at']) 