from django.utils import timezone
from datetime import timedelta
import secrets
import threading
from django.contrib.auth.hashers import make_password, check_password
from django.core.cache import cache

# Thread-local storage for OTP verification locks
_local = threading.local()

def generate_otp(length: int = 6) -> str:
    """Generates a cryptographically secure numeric OTP."""
    return "".join(str(secrets.randbelow(10)) for _ in range(length))

def hash_otp(otp: str) -> str:
    """Hashes the OTP before saving."""
    return make_password(otp)

def verify_otp(provided_otp: str, user, purpose=None) -> bool:
    """
    Verifies a provided OTP against the one stored for the user,
    checking for expiry and matching purpose.
    Includes race condition protection.
    """
    if not all([provided_otp, user, user.mfa_otp, user.mfa_otp_expires_at]):
        return False

    # Create a lock key for this user's OTP verification
    lock_key = f"otp_verify_lock:{user.id}:{purpose or 'default'}"

    # Try to acquire lock (prevents concurrent OTP verification)
    if cache.get(lock_key):
        return False  # Another verification is in progress

    try:
        # Set lock for 10 seconds
        cache.set(lock_key, True, 10)

        # Check if OTP is expired
        if timezone.now() > user.mfa_otp_expires_at:
            return False

        # Check if the purpose matches, if one is provided
        if purpose and user.mfa_otp_purpose != purpose:
            return False

        # Verify the OTP
        is_valid = check_password(provided_otp, user.mfa_otp)

        if is_valid:
            # Immediately invalidate the OTP to prevent reuse
            user.mfa_otp = None
            user.mfa_otp_expires_at = None
            user.mfa_otp_purpose = None
            user.save(update_fields=['mfa_otp', 'mfa_otp_expires_at', 'mfa_otp_purpose'])

        return is_valid

    finally:
        # Always release the lock
        cache.delete(lock_key)

def set_user_otp(user, otp: str, purpose=None):
    """Hashes and saves an OTP, its expiry, and its purpose to the user model."""
    user.mfa_otp = hash_otp(otp)
    user.mfa_otp_expires_at = timezone.now() + timedelta(minutes=10)
    user.mfa_otp_purpose = purpose
    user.save(update_fields=['mfa_otp', 'mfa_otp_expires_at', 'mfa_otp_purpose']) 