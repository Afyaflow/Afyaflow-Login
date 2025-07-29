# Generated migration for email update functionality

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0014_add_patient_profile_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='pending_email',
            field=models.EmailField(blank=True, help_text='Email address pending verification', null=True),
        ),
    ]
