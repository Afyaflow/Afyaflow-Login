# Data migration to clean up existing fake emails

from django.db import migrations


def cleanup_fake_emails(apps, schema_editor):
    """Replace ugly fake emails with smart placeholder emails."""
    User = apps.get_model('users', 'User')
    
    # Find users with fake emails
    fake_email_patterns = [
        '@temp.local',
        '@placeholder.local'
    ]
    
    updated_count = 0
    for pattern in fake_email_patterns:
        users_with_fake_emails = User.objects.filter(email__contains=pattern)
        
        for user in users_with_fake_emails:
            if user.phone_number:
                # Generate smart placeholder email
                normalized_phone = user.phone_number.replace('+', '').replace('-', '')
                new_email = f"phone.{normalized_phone}@afyaflow.app"
                
                # Check if this email already exists
                if not User.objects.filter(email=new_email).exists():
                    user.email = new_email
                    user.save(update_fields=['email'])
                    updated_count += 1
    
    print(f"Updated {updated_count} fake emails to smart placeholder format")


def reverse_cleanup(apps, schema_editor):
    """Reverse migration - not implemented as it's not practical."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0015_add_pending_email_field'),
    ]

    operations = [
        migrations.RunPython(cleanup_fake_emails, reverse_cleanup),
    ]
