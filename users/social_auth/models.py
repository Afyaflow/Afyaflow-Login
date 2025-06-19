from django.db import models
from django.conf import settings

class SocialAccount(models.Model):
    """
    Stores a link between a user in our system and their profile on a third-party provider.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='social_accounts')
    provider = models.CharField(max_length=50, help_text="The name of the social provider (e.g., 'google', 'microsoft').")
    provider_id = models.CharField(max_length=255, help_text="The unique identifier for the user on the provider's platform.")
    
    # Store the user's email as provided by the social platform
    email = models.EmailField(blank=True, null=True)
    
    # Store access and refresh tokens securely
    access_token = models.TextField(blank=True, null=True, help_text="Encrypted access token from the provider.")
    refresh_token = models.TextField(blank=True, null=True, help_text="Encrypted refresh token from the provider.")
    token_expires_at = models.DateTimeField(blank=True, null=True, help_text="The expiry time of the access token.")

    # Additional profile data from the provider
    extra_data = models.JSONField(default=dict, help_text="Provider-specific profile data.")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('provider', 'provider_id')
        indexes = [
            models.Index(fields=['user', 'provider'], name='user_provider_idx'),
            models.Index(fields=['provider', 'provider_id'], name='provider_user_id_idx'),
        ]
        verbose_name = "Social Account"
        verbose_name_plural = "Social Accounts"

    def __str__(self):
        return f"{self.user} - {self.provider.capitalize()}"


class AuthenticationAttempt(models.Model):
    """
    Logs every social authentication attempt for security monitoring and auditing.
    """
    email = models.EmailField(blank=True, null=True, db_index=True)
    provider = models.CharField(max_length=50, blank=True, null=True, db_index=True)
    
    # Client information
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField(blank=True, null=True)
    
    # Status
    success = models.BooleanField()
    failure_reason = models.CharField(max_length=255, blank=True, null=True)
    
    # Timestamp
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        verbose_name = "Authentication Attempt"
        verbose_name_plural = "Authentication Attempts"
        ordering = ['-timestamp']

    def __str__(self):
        status = "Success" if self.success else f"Failure ({self.failure_reason})"
        return f"{self.email or 'Unknown Email'} via {self.provider or 'Unknown Provider'} at {self.timestamp} - {status}" 