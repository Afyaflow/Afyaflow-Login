import uuid
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None  # Disable username field
    email = models.EmailField(_('email address'), unique=True)
    first_name = models.CharField(_('first name'), max_length=150, blank=False)
    last_name = models.CharField(_('last name'), max_length=150, blank=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    # Email verification
    email_verified = models.BooleanField(default=False, help_text="Indicates if the user has verified their email address.")
    
    # MFA fields
    mfa_totp_secret = models.CharField(max_length=32, null=True, blank=True, help_text="Secret for Time-based One-Time Password (TOTP).")
    mfa_totp_setup_complete = models.BooleanField(default=False, help_text="Indicates if the user has successfully verified their TOTP setup.")
    
    # New MFA method flags
    mfa_email_enabled = models.BooleanField(default=False, help_text="Is MFA via Email OTP enabled?")
    mfa_sms_enabled = models.BooleanField(default=False, help_text="Is MFA via SMS OTP enabled?")

    # Phone number for SMS MFA
    phone_number = models.CharField(max_length=20, null=True, blank=True, unique=True)
    phone_number_verified = models.BooleanField(default=False)

    # Fields for temporary OTPs (Email/SMS)
    mfa_otp = models.CharField(max_length=128, null=True, blank=True, help_text="Stores the hashed one-time password.")
    mfa_otp_expires_at = models.DateTimeField(null=True, blank=True, help_text="Expiry time for the one-time password.")
    mfa_otp_purpose = models.CharField(max_length=50, null=True, blank=True, help_text="Purpose of the OTP (e.g., 'phone_verification', 'mfa_setup').")

    # Account status
    is_suspended = models.BooleanField(default=False)
    suspension_reason = models.TextField(null=True, blank=True)
    
    # Password Reset fields
    password_reset_token = models.CharField(max_length=128, null=True, blank=True)
    password_reset_token_expires_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def __str__(self):
        return self.email

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def has_mfa_enabled(self):
        """Check if user has any MFA method enabled."""
        return (self.mfa_totp_setup_complete or
                self.mfa_email_enabled or
                (self.mfa_sms_enabled and self.phone_number_verified))

    def get_enabled_mfa_methods(self):
        """Get list of enabled MFA methods for the user."""
        methods = []
        if self.mfa_totp_setup_complete:
            methods.append("TOTP")
        if self.mfa_email_enabled:
            methods.append("EMAIL")
        if self.mfa_sms_enabled and self.phone_number_verified:
            methods.append("SMS")
        return methods


class RefreshToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='refresh_tokens')
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_revoked = models.BooleanField(default=False)

    class Meta:
        verbose_name = _('refresh token')
        verbose_name_plural = _('refresh tokens')

    def __str__(self):
        return f"{self.user.email} - {self.created_at}"


class AuthenticationAttempt(models.Model):
    """Track authentication attempts for security monitoring and analysis."""

    ATTEMPT_TYPES = [
        ('login', 'Login'),
        ('social_login', 'Social Login'),
        ('password_reset', 'Password Reset'),
        ('mfa_verification', 'MFA Verification'),
        ('registration', 'Registration'),
    ]

    email = models.EmailField(null=True, blank=True, help_text="Email address used in attempt")
    attempt_type = models.CharField(max_length=20, choices=ATTEMPT_TYPES, default='login')
    ip_address = models.GenericIPAddressField(help_text="IP address of the attempt")
    user_agent = models.TextField(help_text="User agent string")
    success = models.BooleanField(help_text="Whether the attempt was successful")
    failure_reason = models.CharField(max_length=255, null=True, blank=True,
                                    help_text="Reason for failure if unsuccessful")
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                           help_text="User associated with the attempt (if known)")
    timestamp = models.DateTimeField(auto_now_add=True)

    # Additional context data
    provider = models.CharField(max_length=50, null=True, blank=True,
                              help_text="Social auth provider (if applicable)")
    metadata = models.JSONField(default=dict, blank=True,
                              help_text="Additional metadata about the attempt")

    class Meta:
        indexes = [
            models.Index(fields=['email', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['attempt_type', 'timestamp']),
            models.Index(fields=['success', 'timestamp']),
        ]
        ordering = ['-timestamp']
        verbose_name = _('authentication attempt')
        verbose_name_plural = _('authentication attempts')

    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"{status} {self.attempt_type} attempt for {self.email or 'Unknown'} at {self.timestamp}"


class BlacklistedToken(models.Model):
    """Track blacklisted JWT tokens for security purposes."""

    token_jti = models.CharField(max_length=255, unique=True, help_text="JWT ID (jti) claim")
    user = models.ForeignKey(User, on_delete=models.CASCADE, help_text="User who owned the token")
    blacklisted_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=255, help_text="Reason for blacklisting")
    expires_at = models.DateTimeField(help_text="When the original token would have expired")

    class Meta:
        indexes = [
            models.Index(fields=['token_jti']),
            models.Index(fields=['user', 'blacklisted_at']),
            models.Index(fields=['expires_at']),
        ]
        ordering = ['-blacklisted_at']
        verbose_name = _('blacklisted token')
        verbose_name_plural = _('blacklisted tokens')

    def __str__(self):
        return f"Blacklisted token for {self.user.email} - {self.reason}"