# Generated by Django 5.2.3 on 2025-06-23 09:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0004_rename_mfa_enabled_user_phone_number_verified_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='email_verified',
            field=models.BooleanField(default=False, help_text='Indicates if the user has verified their email address.'),
        ),
    ]
