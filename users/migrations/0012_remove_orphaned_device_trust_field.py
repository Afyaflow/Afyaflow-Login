# Generated migration to remove orphaned device_trust_enabled field

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0011_add_user_type'),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            DO $$ 
            BEGIN
                -- Check if device_trust_enabled column exists and remove it
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users_user' 
                    AND column_name = 'device_trust_enabled'
                ) THEN
                    ALTER TABLE users_user DROP COLUMN device_trust_enabled;
                END IF;
            END $$;
            """,
            reverse_sql="""
            -- This is irreversible since we don't know the original field definition
            -- If needed, the field can be re-added manually
            """
        ),
    ]
