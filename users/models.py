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
    first_name = models.CharField(_('first name'), max_length=150)
    last_name = models.CharField(_('last name'), max_length=150)
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