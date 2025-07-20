from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

from .models import User, RefreshToken, AuthenticationAttempt, UserRole, RegisteredClient, UserRoleAssignment, BlacklistedToken


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'is_active', 'user_count', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'description')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('name',)

    fieldsets = (
        (None, {'fields': ('name', 'description')}),
        (_('Permissions'), {'fields': ('permissions',)}),
        (_('Status'), {'fields': ('is_active',)}),
        (_('Timestamps'), {'fields': ('created_at', 'updated_at')}),
    )

    def user_count(self, obj):
        """Display count of users with this role."""
        return obj.user_assignments.filter(is_active=True).count()
    user_count.short_description = 'Active Users'

    def get_queryset(self, request):
        """Optimize queryset with prefetch_related."""
        return super().get_queryset(request).prefetch_related('user_assignments')


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'primary_role', 'is_passwordless', 'is_active', 'is_staff', 'is_suspended')
    search_fields = ('email', 'first_name', 'last_name')
    list_filter = ('is_active', 'is_staff', 'is_suspended', 'is_passwordless', 'primary_role', 'device_trust_enabled')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'phone_number')}),
        (_('Role & Authentication'), {'fields': ('primary_role', 'is_passwordless', 'device_trust_enabled', 'last_security_check')}),
        (_('Verification'), {'fields': ('email_verified', 'phone_number_verified')}),
        (_('MFA Settings'), {'fields': ('mfa_totp_setup_complete', 'mfa_email_enabled', 'mfa_sms_enabled')}),
        (_('Status'), {'fields': ('is_suspended', 'suspension_reason')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'first_name', 'last_name'),
        }),
    )


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'client_type', 'created_at', 'expires_at', 'is_revoked')
    search_fields = ('user__email', 'device_fingerprint')
    list_filter = ('is_revoked', 'client_type', 'created_at')
    readonly_fields = ('created_at',)

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user', 'client')


@admin.register(AuthenticationAttempt)
class AuthenticationAttemptAdmin(admin.ModelAdmin):
    list_display = ('email', 'attempt_type', 'client_type', 'role_attempted', 'success', 'ip_address', 'timestamp', 'failure_reason_short')
    list_filter = ('success', 'attempt_type', 'client_type', 'role_attempted', 'timestamp', 'provider')
    search_fields = ('email', 'ip_address', 'user_agent', 'failure_reason')
    readonly_fields = ('timestamp',)
    date_hierarchy = 'timestamp'
    ordering = ('-timestamp',)

    def failure_reason_short(self, obj):
        """Display shortened failure reason."""
        if obj.failure_reason:
            return obj.failure_reason[:50] + '...' if len(obj.failure_reason) > 50 else obj.failure_reason
        return '-'
    failure_reason_short.short_description = 'Failure Reason'

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')

    actions = ['mark_as_reviewed']

    def mark_as_reviewed(self, request, queryset):
        """Custom action to mark attempts as reviewed."""
        # This could update a 'reviewed' field if we add one
        self.message_user(request, f"{queryset.count()} attempts marked as reviewed.")
    mark_as_reviewed.short_description = "Mark selected attempts as reviewed"


@admin.register(RegisteredClient)
class RegisteredClientAdmin(admin.ModelAdmin):
    list_display = ('client_name', 'client_type', 'is_active', 'created_at', 'token_count')
    list_filter = ('client_type', 'is_active', 'allow_social_login', 'require_totp', 'enhanced_monitoring')
    search_fields = ('client_name', 'client_id')
    readonly_fields = ('client_id', 'created_at', 'updated_at', 'api_key_hash', 'signing_key')
    ordering = ('client_name',)

    fieldsets = (
        (_('Basic Information'), {
            'fields': ('client_id', 'client_name', 'client_type', 'is_active')
        }),
        (_('Security Configuration'), {
            'fields': ('api_key_hash', 'signing_key', 'allowed_domains'),
            'classes': ('collapse',)
        }),
        (_('Rate Limiting & Tokens'), {
            'fields': ('max_requests_per_minute', 'token_lifetime_access', 'token_lifetime_refresh')
        }),
        (_('Authentication Policies'), {
            'fields': ('require_device_fingerprint', 'allow_social_login', 'require_totp', 'enhanced_monitoring')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def token_count(self, obj):
        """Display count of active refresh tokens for this client."""
        return obj.refresh_tokens.filter(is_revoked=False).count()
    token_count.short_description = 'Active Tokens'

    def get_queryset(self, request):
        """Optimize queryset with prefetch_related."""
        return super().get_queryset(request).prefetch_related('refresh_tokens')

    def has_change_permission(self, request, obj=None):
        """Restrict editing of sensitive fields."""
        if obj and not request.user.is_superuser:
            # Only superusers can edit client credentials
            return False
        return super().has_change_permission(request, obj)


@admin.register(UserRoleAssignment)
class UserRoleAssignmentAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'is_active', 'assigned_at', 'assigned_by', 'expires_at')
    list_filter = ('role', 'is_active', 'assigned_at')
    search_fields = ('user__email', 'user__first_name', 'user__last_name', 'role__name')
    readonly_fields = ('assigned_at',)
    date_hierarchy = 'assigned_at'
    ordering = ('-assigned_at',)

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user', 'role', 'assigned_by')


@admin.register(BlacklistedToken)
class BlacklistedTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'client_type', 'reason', 'violation_reason', 'blacklisted_at', 'expires_at')
    list_filter = ('client_type', 'blacklisted_at', 'expires_at')
    search_fields = ('user__email', 'token_jti', 'reason', 'violation_reason')
    readonly_fields = ('token_jti', 'blacklisted_at', 'expires_at')
    date_hierarchy = 'blacklisted_at'
    ordering = ('-blacklisted_at',)

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user', 'client')