# Generated migration to fix the security_context field issue
# This migration only fixes the immediate problem causing the login error

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_increase_refresh_token_length'),
    ]

    operations = [
        # Fix the immediate issue: make security_context nullable or remove it
        # This is the minimal fix to get the login working again
        
        migrations.RunSQL(
            sql="""
            DO $$ 
            BEGIN
                -- Check if security_context column exists and make it nullable
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users_authenticationattempt' 
                    AND column_name = 'security_context'
                ) THEN
                    -- Make the column nullable to fix the immediate error
                    ALTER TABLE users_authenticationattempt 
                    ALTER COLUMN security_context DROP NOT NULL;
                    
                    -- Set a default value for existing NULL values
                    UPDATE users_authenticationattempt 
                    SET security_context = '{}' 
                    WHERE security_context IS NULL;
                    
                    -- Set default for future inserts
                    ALTER TABLE users_authenticationattempt 
                    ALTER COLUMN security_context SET DEFAULT '{}';
                END IF;
            END $$;
            """,
            reverse_sql="""
            DO $$ 
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users_authenticationattempt' 
                    AND column_name = 'security_context'
                ) THEN
                    ALTER TABLE users_authenticationattempt 
                    ALTER COLUMN security_context SET NOT NULL;
                END IF;
            END $$;
            """
        ),
        
        # Also fix any other fields that might cause similar issues
        migrations.RunSQL(
            sql="""
            DO $$ 
            BEGIN
                -- Fix client_type field if it exists
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users_authenticationattempt' 
                    AND column_name = 'client_type'
                ) THEN
                    ALTER TABLE users_authenticationattempt 
                    ALTER COLUMN client_type DROP NOT NULL;
                END IF;
                
                -- Fix role_attempted field if it exists
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users_authenticationattempt' 
                    AND column_name = 'role_attempted'
                ) THEN
                    ALTER TABLE users_authenticationattempt 
                    ALTER COLUMN role_attempted DROP NOT NULL;
                END IF;
            END $$;
            """,
            reverse_sql="-- Reverse operations would make fields NOT NULL again"
        ),
    ]
