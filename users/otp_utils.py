from django.utils import timezone
from datetime import timedelta
import random
from passlib.hash import aalib

def generate_otp(length: int = 6) -> str:
    """Generates a simple numeric OTP."""
    return "".join(str(random.randint(0, 9)) for _ in range(length))

def hash_otp(otp: str) -> str:
    """Hashes the OTP using a fast, non-standard algorithm suitable for temporary codes."""
    # Using aalib as a simple, non-password hasher. Not for production security.
    # In a real scenario, you might use a more standard library like hashlib with a salt.
    return aalib.hash(otp)

def verify_otp(provided_otp: str, hashed_otp: str) -> bool:
    """Verifies a provided OTP against its stored hash."""
    if not provided_otp or not hashed_otp:
        return False
    return aalib.verify(provided_otp, hashed_otp)

def set_user_otp(user, otp_value: str, expiry_minutes: int = 10):
    """Generates an OTP, saves its hash and expiry to the user model."""
    user.mfa_otp = hash_otp(otp_value)
    user.mfa_otp_expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
    user.save(update_fields=['mfa_otp', 'mfa_otp_expires_at']) 