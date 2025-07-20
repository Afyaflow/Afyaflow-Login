import uuid
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.utils import timezone


class UserRole(models.Model):
    """
    Defines user roles in the system (PATIENT, PROVIDER, ADMIN).
    Supports role-based authentication and access control.
    """

    ROLE_CHOICES = [
        ('PATIENT', 'Patient'),
        ('PROVIDER', 'Provider'),
        ('ADMIN', 'Admin'),
    ]

    name = models.CharField(
        max_length=20,
        unique=True,
        choices=ROLE_CHOICES,
        help_text="Role name (PATIENT, PROVIDER, ADMIN)"
    )
    description = models.TextField(
        blank=True,
        help_text="Description of the role and its permissions"
    )
    permissions = models.JSONField(
        default=list,
        help_text="List of permissions associated with this role"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this role is currently active"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('user role')
        verbose_name_plural = _('user roles')
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['is_active']),
        ]
        ordering = ['name']

    def __str__(self):
        return self.name

    def clean(self):
        """Validate role data."""
        super().clean()
        if self.name and self.name not in dict(self.ROLE_CHOICES):
            raise ValidationError(f"Invalid role name: {self.name}")

    @classmethod
    def get_default_permissions(cls, role_name):
        """Get default permissions for a role."""
        default_permissions = {
            'PATIENT': [
                'view_own_profile',
                'update_own_profile',
                'view_own_medical_records',
                'access_patient_apps'
            ],
            'PROVIDER': [
                'view_own_profile',
                'update_own_profile',
                'view_patient_records',
                'create_medical_records',
                'update_medical_records',
                'access_provider_apps',
                'manage_organization_patients'
            ],
            'ADMIN': [
                'view_all_users',
                'manage_users',
                'manage_organizations',
                'view_system_logs',
                'manage_system_settings',
                'access_admin_interface'
            ],
            'OPERATIONS': [
                'view_all_users',
                'view_system_logs',
                'manage_system_settings',
                'access_admin_interface',
                'cross_tenant_access',
                'system_maintenance',
                'technical_support',
                'service_account_management',
                'global_monitoring'
            ]
        }
        return default_permissions.get(role_name, [])


class RegisteredClient(models.Model):
    """
    Represents a registered client application that can authenticate with the service.
    Provides client-specific security policies and token isolation.
    """

    CLIENT_TYPES = [
        ('PATIENT_WEB', 'Patient Web Application (Waridi)'),
        ('PATIENT_MOBILE', 'Patient Mobile Application (Afyaflow Mobile)'),
        ('PROVIDER_WEB', 'Provider Web Application'),
        ('PROVIDER_MOBILE', 'Provider Mobile Application'),
        ('ADMIN_WEB', 'Admin Web Application'),
    ]

    client_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique client identifier"
    )
    client_name = models.CharField(
        max_length=100,
        help_text="Human-readable client name"
    )
    client_type = models.CharField(
        max_length=20,
        choices=CLIENT_TYPES,
        help_text="Type of client application"
    )
    allowed_domains = models.JSONField(
        default=list,
        help_text="List of allowed domains for this client"
    )
    api_key_hash = models.CharField(
        max_length=255,
        help_text="Hashed API key for client authentication"
    )
    signing_key = models.TextField(
        help_text="Unique JWT signing key for this client"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this client is currently active"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Security policy fields
    max_requests_per_minute = models.IntegerField(
        default=60,
        help_text="Rate limit for this client"
    )
    token_lifetime_access = models.IntegerField(
        default=60,
        help_text="Access token lifetime in minutes"
    )
    token_lifetime_refresh = models.IntegerField(
        default=10080,  # 7 days
        help_text="Refresh token lifetime in minutes"
    )
    require_device_fingerprint = models.BooleanField(
        default=False,
        help_text="Whether device fingerprinting is required"
    )
    allow_social_login = models.BooleanField(
        default=True,
        help_text="Whether social login is allowed for this client"
    )
    require_totp = models.BooleanField(
        default=False,
        help_text="Whether TOTP is required for this client"
    )
    enhanced_monitoring = models.BooleanField(
        default=False,
        help_text="Whether enhanced security monitoring is enabled"
    )

    # Migration support fields
    supports_new_token_format = models.BooleanField(
        default=False,
        help_text="Whether this client supports the new gateway-compliant token format"
    )
    legacy_token_support_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Date until which legacy tokens will be supported for this client"
    )
    migration_status = models.CharField(
        max_length=20,
        choices=[
            ('LEGACY', 'Legacy Only'),
            ('DUAL', 'Dual Support'),
            ('NEW', 'New Format Only')
        ],
        default='LEGACY',
        help_text="Current migration status for this client"
    )

    class Meta:
        verbose_name = _('registered client')
        verbose_name_plural = _('registered clients')
        indexes = [
            models.Index(fields=['client_type']),
            models.Index(fields=['is_active']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['client_name']

    def __str__(self):
        return f"{self.client_name} ({self.client_type})"

    def clean(self):
        """Validate client data."""
        super().clean()
        if self.client_type and self.client_type not in dict(self.CLIENT_TYPES):
            raise ValidationError(f"Invalid client type: {self.client_type}")

    @property
    def security_policy(self):
        """Get the security policy for this client."""
        return {
            'max_requests_per_minute': self.max_requests_per_minute,
            'token_lifetime_access': self.token_lifetime_access,
            'token_lifetime_refresh': self.token_lifetime_refresh,
            'require_device_fingerprint': self.require_device_fingerprint,
            'allow_social_login': self.allow_social_login,
            'require_totp': self.require_totp,
            'enhanced_monitoring': self.enhanced_monitoring,
        }

    @classmethod
    def get_default_security_policy(cls, client_type):
        """Get default security policy for a client type."""
        policies = {
            'PATIENT_WEB': {
                'max_requests_per_minute': 60,
                'token_lifetime_access': 60,
                'token_lifetime_refresh': 43200,  # 30 days
                'require_device_fingerprint': True,
                'allow_social_login': False,
                'require_totp': False,
                'enhanced_monitoring': False,
            },
            'PATIENT_MOBILE': {
                'max_requests_per_minute': 100,
                'token_lifetime_access': 60,
                'token_lifetime_refresh': 43200,  # 30 days
                'require_device_fingerprint': True,
                'allow_social_login': False,
                'require_totp': False,
                'enhanced_monitoring': False,
            },
            'PROVIDER_WEB': {
                'max_requests_per_minute': 120,
                'token_lifetime_access': 15,
                'token_lifetime_refresh': 10080,  # 7 days
                'require_device_fingerprint': False,
                'allow_social_login': True,
                'require_totp': True,
                'enhanced_monitoring': True,
            },
            'PROVIDER_MOBILE': {
                'max_requests_per_minute': 150,
                'token_lifetime_access': 15,
                'token_lifetime_refresh': 10080,  # 7 days
                'require_device_fingerprint': False,
                'allow_social_login': True,
                'require_totp': True,
                'enhanced_monitoring': True,
            },
            'ADMIN_WEB': {
                'max_requests_per_minute': 200,
                'token_lifetime_access': 15,
                'token_lifetime_refresh': 1440,  # 1 day
                'require_device_fingerprint': True,
                'allow_social_login': False,
                'require_totp': True,
                'enhanced_monitoring': True,
            },
        }
        return policies.get(client_type, {})


class ServiceAccount(models.Model):
    """
    Service Account for inter-service authentication.
    Supports dynamic configuration via environment variables.
    """

    service_id = models.CharField(
        max_length=100,
        unique=True,
        help_text="Unique service identifier (e.g., billing-svc-123abc)"
    )
    service_type = models.CharField(
        max_length=50,
        help_text="Type of service (e.g., internal-billing, internal-patients)"
    )
    permissions = models.JSONField(
        default=list,
        help_text="List of permissions for this service (e.g., ['read:billing', 'write:billing'])"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this service account is currently active"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('service account')
        verbose_name_plural = _('service accounts')
        indexes = [
            models.Index(fields=['service_id']),
            models.Index(fields=['service_type']),
            models.Index(fields=['is_active']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['service_id']

    def __str__(self):
        return f"{self.service_id} ({self.service_type})"

    def clean(self):
        """Validate service account data."""
        super().clean()
        if not self.service_id:
            raise ValidationError("Service ID is required")
        if not self.service_type:
            raise ValidationError("Service type is required")

    @classmethod
    def load_from_environment(cls):
        """Load service accounts from environment variables."""
        from django.conf import settings

        service_ids = getattr(settings, 'SERVICE_ACCOUNT_IDS', [])

        for service_id in service_ids:
            # Normalize service ID for environment variable names
            normalized_id = service_id.upper().replace('-', '_').replace('.', '_')

            service_type = getattr(settings, f'SERVICE_ACCOUNT_{normalized_id}_TYPE', None)
            permissions_str = getattr(settings, f'SERVICE_ACCOUNT_{normalized_id}_PERMISSIONS', '')

            if service_type:
                permissions = permissions_str.split(',') if permissions_str else []
                permissions = [p.strip() for p in permissions if p.strip()]

                cls.objects.update_or_create(
                    service_id=service_id,
                    defaults={
                        'service_type': service_type,
                        'permissions': permissions,
                        'is_active': True
                    }
                )

    def has_permission(self, permission):
        """Check if service account has a specific permission."""
        return permission in self.permissions

    def get_permissions_for_resource(self, resource):
        """Get permissions for a specific resource."""
        return [p for p in self.permissions if p.startswith(f'{resource}:')]

    @classmethod
    def load_from_environment_with_counts(cls, force_update=False):
        """Load service accounts from environment and return counts."""
        from django.conf import settings

        service_ids = getattr(settings, 'SERVICE_ACCOUNT_IDS', [])
        created_count = 0
        updated_count = 0

        for service_id in service_ids:
            # Normalize service ID for environment variable names
            normalized_id = service_id.upper().replace('-', '_').replace('.', '_')

            service_type = getattr(settings, f'SERVICE_ACCOUNT_{normalized_id}_TYPE', None)
            permissions_str = getattr(settings, f'SERVICE_ACCOUNT_{normalized_id}_PERMISSIONS', '')

            if service_type:
                permissions = permissions_str.split(',') if permissions_str else []
                permissions = [p.strip() for p in permissions if p.strip()]

                service_account, created = cls.objects.update_or_create(
                    service_id=service_id,
                    defaults={
                        'service_type': service_type,
                        'permissions': permissions,
                        'is_active': True
                    }
                )

                if created:
                    created_count += 1
                elif force_update:
                    updated_count += 1

        return created_count, updated_count


class OrganizationContext(models.Model):
    """
    Extended organization context for OCT tokens.
    Supports hierarchical organization structure and service subscriptions.
    """

    organization_id = models.UUIDField(
        help_text="Primary organization identifier"
    )
    branch_id = models.UUIDField(
        null=True,
        blank=True,
        help_text="Branch identifier within the organization"
    )
    cluster_id = models.UUIDField(
        null=True,
        blank=True,
        help_text="Cluster identifier for regional grouping"
    )
    subscribed_services = models.JSONField(
        default=list,
        help_text="List of services this organization has access to"
    )
    organization_permissions = models.JSONField(
        default=dict,
        help_text="Organization-specific permissions mapping"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this organization context is active"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('organization context')
        verbose_name_plural = _('organization contexts')
        indexes = [
            models.Index(fields=['organization_id']),
            models.Index(fields=['branch_id']),
            models.Index(fields=['cluster_id']),
            models.Index(fields=['is_active']),
            models.Index(fields=['created_at']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['organization_id', 'branch_id', 'cluster_id'],
                name='unique_org_branch_cluster'
            )
        ]
        ordering = ['organization_id', 'branch_id', 'cluster_id']

    def __str__(self):
        parts = [str(self.organization_id)]
        if self.branch_id:
            parts.append(f"Branch: {self.branch_id}")
        if self.cluster_id:
            parts.append(f"Cluster: {self.cluster_id}")
        return " | ".join(parts)

    def clean(self):
        """Validate organization context data."""
        super().clean()
        if not self.organization_id:
            raise ValidationError("Organization ID is required")

    def get_full_context(self):
        """Get complete organization context for OCT token."""
        return {
            'orgId': str(self.organization_id),
            'branchId': str(self.branch_id) if self.branch_id else None,
            'clusterId': str(self.cluster_id) if self.cluster_id else None,
            'permissions': self.organization_permissions,
            'subscribedServices': self.subscribed_services
        }

    def has_service_access(self, service_name):
        """Check if organization has access to a specific service."""
        return service_name in self.subscribed_services

    def get_service_permissions(self, service_name):
        """Get permissions for a specific service."""
        return self.organization_permissions.get(service_name, [])


class UserRoleAssignment(models.Model):
    """
    Represents the assignment of a role to a user.
    Supports multiple roles per user with audit trail.
    """

    user = models.ForeignKey(
        'User',  # Forward reference since User is defined later
        on_delete=models.CASCADE,
        related_name='role_assignments',
        help_text="User assigned to this role"
    )
    role = models.ForeignKey(
        UserRole,
        on_delete=models.CASCADE,
        related_name='user_assignments',
        help_text="Role assigned to the user"
    )
    assigned_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When the role was assigned"
    )
    assigned_by = models.ForeignKey(
        'User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='role_assignments_made',
        help_text="User who made this role assignment"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this role assignment is currently active"
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this role assignment expires (optional)"
    )

    class Meta:
        verbose_name = _('user role assignment')
        verbose_name_plural = _('user role assignments')
        indexes = [
            models.Index(fields=['user', 'role']),
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['role', 'is_active']),
            models.Index(fields=['assigned_at']),
            models.Index(fields=['expires_at']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'role'],
                condition=models.Q(is_active=True),
                name='unique_active_user_role'
            )
        ]
        ordering = ['-assigned_at']

    def __str__(self):
        return f"{self.user.email} - {self.role.name}"

    def clean(self):
        """Validate role assignment."""
        super().clean()

        # Check if expires_at is in the future
        if self.expires_at and self.expires_at <= timezone.now():
            raise ValidationError("Expiration date must be in the future")

    @property
    def is_expired(self):
        """Check if this role assignment has expired."""
        if not self.expires_at:
            return False
        from django.utils import timezone
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        """Check if this role assignment is currently valid."""
        return self.is_active and not self.is_expired


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

    # Role and authentication enhancement fields
    primary_role = models.ForeignKey(
        UserRole,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='primary_users',
        help_text="Primary role for this user"
    )
    is_passwordless = models.BooleanField(
        default=False,
        help_text="Whether this user uses passwordless authentication (patients)"
    )
    device_trust_enabled = models.BooleanField(
        default=False,
        help_text="Whether device trust is enabled for extended sessions"
    )
    last_security_check = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time security policies were checked for this user"
    )

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

    # Role-related methods
    def get_active_roles(self):
        """Get all active roles for this user."""
        return UserRole.objects.filter(
            user_assignments__user=self,
            user_assignments__is_active=True,
            is_active=True
        ).distinct()

    def has_role(self, role_name):
        """Check if user has a specific role."""
        return self.get_active_roles().filter(name=role_name).exists()

    def is_patient(self):
        """Check if user has PATIENT role."""
        return self.has_role('PATIENT')

    def is_provider(self):
        """Check if user has PROVIDER role."""
        return self.has_role('PROVIDER')

    def is_admin_user(self):
        """Check if user has ADMIN role."""
        return self.has_role('ADMIN')

    def is_operations_user(self):
        """Check if user has OPERATIONS role."""
        return self.has_role('OPERATIONS')

    def get_primary_role_name(self):
        """Get the name of the primary role."""
        return self.primary_role.name if self.primary_role else None

    def assign_role(self, role_name, assigned_by=None):
        """Assign a role to this user."""
        try:
            role = UserRole.objects.get(name=role_name, is_active=True)
            assignment, created = UserRoleAssignment.objects.get_or_create(
                user=self,
                role=role,
                defaults={
                    'assigned_by': assigned_by,
                    'is_active': True
                }
            )

            # Set as primary role if user doesn't have one
            if not self.primary_role:
                self.primary_role = role
                self.save(update_fields=['primary_role'])

            return assignment
        except UserRole.DoesNotExist:
            raise ValueError(f"Role '{role_name}' does not exist or is not active")

    def remove_role(self, role_name):
        """Remove a role from this user."""
        UserRoleAssignment.objects.filter(
            user=self,
            role__name=role_name,
            is_active=True
        ).update(is_active=False)

        # Clear primary role if it was removed
        if self.primary_role and self.primary_role.name == role_name:
            # Set to another active role if available
            other_roles = self.get_active_roles().exclude(name=role_name)
            self.primary_role = other_roles.first()
            self.save(update_fields=['primary_role'])

    def requires_totp_for_client(self, client_type):
        """Check if TOTP is required for this user with a specific client type."""
        if self.is_provider() and client_type in ['PROVIDER_WEB', 'PROVIDER_MOBILE']:
            return True
        if self.is_admin_user():
            return True
        if self.is_operations_user():
            return True  # Operations users always require TOTP for security
        return False

    def get_token_lifetime_for_client(self, client_type, token_type='access'):
        """Get appropriate token lifetime based on user role and client type."""
        if self.is_patient() and client_type in ['PATIENT_WEB', 'PATIENT_MOBILE']:
            if token_type == 'access':
                return 60  # 1 hour
            else:  # refresh
                return 43200  # 30 days
        elif self.is_provider() and client_type in ['PROVIDER_WEB', 'PROVIDER_MOBILE']:
            if token_type == 'access':
                return 15  # 15 minutes
            else:  # refresh
                return 10080  # 7 days
        elif self.is_admin_user():
            if token_type == 'access':
                return 15  # 15 minutes
            else:  # refresh
                return 1440  # 1 day
        elif self.is_operations_user():
            if token_type == 'access':
                return 15  # 15 minutes (same as admin for security)
            else:  # refresh
                return 1440  # 1 day (same as admin for security)

        # Default fallback
        return 60 if token_type == 'access' else 10080


class RefreshToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='refresh_tokens')
    token = models.CharField(max_length=512, unique=True)  # Increased from 255 to 512 for JWT tokens
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_revoked = models.BooleanField(default=False)

    # Client context fields
    client = models.ForeignKey(
        RegisteredClient,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='refresh_tokens',
        help_text="Client application that issued this token"
    )
    client_type = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        help_text="Type of client application"
    )
    device_fingerprint = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Device fingerprint for security tracking"
    )

    class Meta:
        verbose_name = _('refresh token')
        verbose_name_plural = _('refresh tokens')
        indexes = [
            models.Index(fields=['user', 'client']),
            models.Index(fields=['client_type']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['is_revoked']),
        ]

    def __str__(self):
        client_info = f" ({self.client_type})" if self.client_type else ""
        return f"{self.user.email}{client_info} - {self.created_at}"

    def is_valid_for_client(self, client_id):
        """Check if this token is valid for the specified client."""
        if not self.client:
            return False
        return str(self.client.client_id) == str(client_id) and not self.is_revoked

    def revoke(self, reason="Manual revocation"):
        """Revoke this refresh token."""
        self.is_revoked = True
        self.save(update_fields=['is_revoked'])


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

    # Client and role context fields
    client = models.ForeignKey(
        RegisteredClient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='authentication_attempts',
        help_text="Client application used for this attempt"
    )
    client_type = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        help_text="Type of client application"
    )
    role_attempted = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        help_text="Role that was being authenticated for"
    )
    security_context = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional security context and metadata"
    )

    @staticmethod
    def truncate_failure_reason(reason: str) -> str:
        """
        Truncate failure reason to fit the database field constraint.

        Args:
            reason: The failure reason string

        Returns:
            Truncated reason that fits within 255 characters
        """
        if not reason:
            return reason

        max_length = 255
        if len(reason) <= max_length:
            return reason

        # Truncate and add ellipsis to indicate truncation
        return reason[:max_length-3] + '...'

    class Meta:
        indexes = [
            models.Index(fields=['email', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['attempt_type', 'timestamp']),
            models.Index(fields=['success', 'timestamp']),
            models.Index(fields=['client', 'timestamp']),
            models.Index(fields=['client_type', 'timestamp']),
            models.Index(fields=['role_attempted', 'timestamp']),
        ]
        ordering = ['-timestamp']
        verbose_name = _('authentication attempt')
        verbose_name_plural = _('authentication attempts')

    def __str__(self):
        status = "Success" if self.success else "Failed"
        client_info = f" via {self.client_type}" if self.client_type else ""
        role_info = f" for {self.role_attempted}" if self.role_attempted else ""
        return f"{status} {self.attempt_type} attempt{client_info}{role_info} for {self.email or 'Unknown'} at {self.timestamp}"


class BlacklistedToken(models.Model):
    """Track blacklisted JWT tokens for security purposes."""

    token_jti = models.CharField(max_length=255, unique=True, help_text="JWT ID (jti) claim")
    user = models.ForeignKey(User, on_delete=models.CASCADE, help_text="User who owned the token")
    blacklisted_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=255, help_text="Reason for blacklisting")
    expires_at = models.DateTimeField(help_text="When the original token would have expired")

    # Client context fields
    client = models.ForeignKey(
        RegisteredClient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='blacklisted_tokens',
        help_text="Client application that issued this token"
    )
    client_type = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        help_text="Type of client application"
    )
    violation_reason = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Specific security violation that caused blacklisting"
    )

    class Meta:
        indexes = [
            models.Index(fields=['token_jti']),
            models.Index(fields=['user', 'blacklisted_at']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['client', 'blacklisted_at']),
            models.Index(fields=['client_type']),
        ]
        ordering = ['-blacklisted_at']
        verbose_name = _('blacklisted token')
        verbose_name_plural = _('blacklisted tokens')

    def __str__(self):
        client_info = f" ({self.client_type})" if self.client_type else ""
        return f"Blacklisted token for {self.user.email}{client_info} - {self.reason}"

    @classmethod
    def blacklist_token(cls, token_jti, user, reason, expires_at, client=None, client_type=None, violation_reason=None):
        """Convenience method to blacklist a token with full context."""
        return cls.objects.create(
            token_jti=token_jti,
            user=user,
            reason=reason,
            expires_at=expires_at,
            client=client,
            client_type=client_type,
            violation_reason=violation_reason
        )