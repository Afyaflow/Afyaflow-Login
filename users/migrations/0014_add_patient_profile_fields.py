# Generated migration for dual-role support

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0013_remove_orphaned_is_passwordless_field'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='patient_profile_enabled',
            field=models.BooleanField(default=False, help_text='Whether this user can access patient services'),
        ),
        migrations.AddField(
            model_name='user',
            name='patient_services_first_used',
            field=models.DateTimeField(blank=True, help_text='When user first accessed patient services', null=True),
        ),
    ]
