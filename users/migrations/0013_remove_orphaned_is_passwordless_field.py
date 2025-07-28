# Generated migration to remove orphaned is_passwordless field

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0012_remove_orphaned_device_trust_field'),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            DO $$ 
            BEGIN
                -- Check if is_passwordless column exists and remove it
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users_user' 
                    AND column_name = 'is_passwordless'
                ) THEN
                    ALTER TABLE users_user DROP COLUMN is_passwordless;
                END IF;
            END $$;
            """,
            reverse_sql="""
            -- This is irreversible since we don't know the original field definition
            -- If needed, the field can be re-added manually
            """
        ),
    ]
