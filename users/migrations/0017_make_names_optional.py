# Generated migration to make first_name and last_name optional for patients

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0016_cleanup_fake_emails'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='first_name',
            field=models.CharField(blank=True, max_length=150, verbose_name='first name'),
        ),
        migrations.AlterField(
            model_name='user',
            name='last_name',
            field=models.CharField(blank=True, max_length=150, verbose_name='last name'),
        ),
    ]
