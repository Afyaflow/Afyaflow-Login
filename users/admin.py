from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

from .models import User, RefreshToken, AuthenticationAttempt


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'user_type', 'patient_profile_enabled', 'is_active', 'is_staff', 'is_suspended')
    search_fields = ('email', 'first_name', 'last_name')
    list_filter = ('user_type', 'patient_profile_enabled', 'is_active', 'is_staff', 'is_suspended', 'email_verified')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'phone_number')}),
        (_('User Type'), {'fields': ('user_type',)}),
        (_('Dual Role Support'), {'fields': ('patient_profile_enabled', 'patient_services_first_used')}),
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
            'fields': ('email', 'password1', 'password2', 'first_name', 'last_name', 'user_type'),
        }),
    )

    def get_form(self, request, obj=None, **kwargs):
        """Customize form based on user type."""
        form = super().get_form(request, obj, **kwargs)

        # For operations users, make them staff by default
        if obj and obj.user_type == 'operations':
            if 'is_staff' in form.base_fields:
                form.base_fields['is_staff'].initial = True

        return form

    def save_model(self, request, obj, form, change):
        """Custom save logic for different user types."""
        # For new operations users, ensure they have staff privileges
        if not change and obj.user_type == 'operations':
            obj.is_staff = True

        super().save_model(request, obj, form, change)

    def get_readonly_fields(self, request, obj=None):
        """Make certain fields readonly based on user type."""
        readonly_fields = list(super().get_readonly_fields(request, obj))

        # For patients, make certain fields readonly since they use passwordless auth
        if obj and obj.user_type == 'patient':
            readonly_fields.extend(['password'])

        return readonly_fields


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'expires_at', 'is_revoked')
    search_fields = ('user__email',)
    list_filter = ('is_revoked', 'created_at')


@admin.register(AuthenticationAttempt)
class AuthenticationAttemptAdmin(admin.ModelAdmin):
    list_display = ('email', 'attempt_type', 'success', 'ip_address', 'timestamp', 'failure_reason_short')
    list_filter = ('success', 'attempt_type', 'timestamp', 'provider')
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