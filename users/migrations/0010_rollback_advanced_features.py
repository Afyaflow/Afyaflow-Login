# Generated rollback migration to undo migrations 0010, 0011, 0012, 0013
# This migration removes all advanced features added in those migrations
# while preserving user data and core authentication functionality.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_increase_refresh_token_length'),
    ]

    operations = [
        # ========================================================================
        # STEP 1: Remove indexes added in 0013
        # ========================================================================
        
        # Remove OrganizationContext indexes (if they exist)
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS users_organ_organiz_87bea3_idx;",
            reverse_sql="CREATE INDEX IF NOT EXISTS users_organ_organiz_87bea3_idx ON users_organizationcontext (organization_id);"
        ),
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS users_organ_branch__ba93db_idx;",
            reverse_sql="CREATE INDEX IF NOT EXISTS users_organ_branch__ba93db_idx ON users_organizationcontext (branch_id);"
        ),
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS users_organ_cluster_e12a97_idx;",
            reverse_sql="CREATE INDEX IF NOT EXISTS users_organ_cluster_e12a97_idx ON users_organizationcontext (cluster_id);"
        ),
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS users_organ_is_acti_507daa_idx;",
            reverse_sql="CREATE INDEX IF NOT EXISTS users_organ_is_acti_507daa_idx ON users_organizationcontext (is_active);"
        ),
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS users_organ_created_a03c49_idx;",
            reverse_sql="CREATE INDEX IF NOT EXISTS users_organ_created_a03c49_idx ON users_organizationcontext (created_at);"
        ),
        
        # Remove ServiceAccount indexes (if they exist)
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS users_servi_service_51e669_idx;",
            reverse_sql="CREATE INDEX IF NOT EXISTS users_servi_service_51e669_idx ON users_serviceaccount (service_id);"
        ),
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS users_servi_service_74b3ee_idx;",
            reverse_sql="CREATE INDEX IF NOT EXISTS users_servi_service_74b3ee_idx ON users_serviceaccount (service_type);"
        ),
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS users_servi_is_acti_6dc127_idx;",
            reverse_sql="CREATE INDEX IF NOT EXISTS users_servi_is_acti_6dc127_idx ON users_serviceaccount (is_active);"
        ),
        migrations.RunSQL(
            sql="DROP INDEX IF EXISTS users_servi_created_4da095_idx;",
            reverse_sql="CREATE INDEX IF NOT EXISTS users_servi_created_4da095_idx ON users_serviceaccount (created_at);"
        ),

        # ========================================================================
        # STEP 2: Drop tables added in 0012 (ServiceAccount, OrganizationContext)
        # ========================================================================
        
        migrations.RunSQL(
            sql="DROP TABLE IF EXISTS users_serviceaccount CASCADE;",
            reverse_sql="-- ServiceAccount table would need to be recreated"
        ),
        
        migrations.RunSQL(
            sql="DROP TABLE IF EXISTS users_organizationcontext CASCADE;",
            reverse_sql="-- OrganizationContext table would need to be recreated"
        ),
        
        # Remove OPERATIONS role
        migrations.RunSQL(
            sql="DELETE FROM users_userrole WHERE name = 'OPERATIONS';",
            reverse_sql="-- OPERATIONS role would need to be recreated"
        ),
        
        # Restore original UserRole constraint (remove OPERATIONS)
        migrations.RunSQL(
            sql=[
                "ALTER TABLE users_userrole DROP CONSTRAINT IF EXISTS users_userrole_name_check;",
                "ALTER TABLE users_userrole ADD CONSTRAINT users_userrole_name_check CHECK (name IN ('PATIENT', 'PROVIDER', 'ADMIN'));",
            ],
            reverse_sql=[
                "ALTER TABLE users_userrole DROP CONSTRAINT IF EXISTS users_userrole_name_check;",
                "ALTER TABLE users_userrole ADD CONSTRAINT users_userrole_name_check CHECK (name IN ('PATIENT', 'PROVIDER', 'ADMIN', 'OPERATIONS'));",
            ]
        ),

        # ========================================================================
        # STEP 3: Remove fields added to existing models in 0011
        # ========================================================================
        
        # Remove fields from AuthenticationAttempt
        migrations.RunSQL(
            sql="ALTER TABLE users_authenticationattempt DROP COLUMN IF EXISTS client_id CASCADE;",
            reverse_sql="-- client field would need to be recreated"
        ),
        migrations.RunSQL(
            sql="ALTER TABLE users_authenticationattempt DROP COLUMN IF EXISTS client_type;",
            reverse_sql="-- client_type field would need to be recreated"
        ),
        migrations.RunSQL(
            sql="ALTER TABLE users_authenticationattempt DROP COLUMN IF EXISTS role_attempted;",
            reverse_sql="-- role_attempted field would need to be recreated"
        ),
        migrations.RunSQL(
            sql="ALTER TABLE users_authenticationattempt DROP COLUMN IF EXISTS security_context;",
            reverse_sql="-- security_context field would need to be recreated"
        ),
        
        # Remove fields from BlacklistedToken
        migrations.RunSQL(
            sql="ALTER TABLE users_blacklistedtoken DROP COLUMN IF EXISTS client_id CASCADE;",
            reverse_sql="-- client field would need to be recreated"
        ),
        migrations.RunSQL(
            sql="ALTER TABLE users_blacklistedtoken DROP COLUMN IF EXISTS client_type;",
            reverse_sql="-- client_type field would need to be recreated"
        ),
        migrations.RunSQL(
            sql="ALTER TABLE users_blacklistedtoken DROP COLUMN IF EXISTS violation_reason;",
            reverse_sql="-- violation_reason field would need to be recreated"
        ),
        
        # Remove fields from RefreshToken
        migrations.RunSQL(
            sql="ALTER TABLE users_refreshtoken DROP COLUMN IF EXISTS client_id CASCADE;",
            reverse_sql="-- client field would need to be recreated"
        ),
        migrations.RunSQL(
            sql="ALTER TABLE users_refreshtoken DROP COLUMN IF EXISTS client_type;",
            reverse_sql="-- client_type field would need to be recreated"
        ),
        migrations.RunSQL(
            sql="ALTER TABLE users_refreshtoken DROP COLUMN IF EXISTS security_context;",
            reverse_sql="-- security_context field would need to be recreated"
        ),

        # ========================================================================
        # STEP 4: Drop tables added in 0010 (RegisteredClient, UserRole)
        # ========================================================================
        
        migrations.RunSQL(
            sql="DROP TABLE IF EXISTS users_registeredclient CASCADE;",
            reverse_sql="-- RegisteredClient table would need to be recreated"
        ),
        
        migrations.RunSQL(
            sql="DROP TABLE IF EXISTS users_userrole CASCADE;",
            reverse_sql="-- UserRole table would need to be recreated"
        ),

        # ========================================================================
        # STEP 5: Clean up any remaining foreign key constraints
        # ========================================================================
        
        migrations.RunSQL(
            sql="""
            DO $$ 
            DECLARE 
                r RECORD;
            BEGIN
                -- Drop any remaining foreign key constraints that reference deleted tables
                FOR r IN (
                    SELECT constraint_name, table_name 
                    FROM information_schema.table_constraints 
                    WHERE constraint_type = 'FOREIGN KEY' 
                    AND table_schema = 'public'
                    AND (
                        constraint_name LIKE '%registeredclient%' OR
                        constraint_name LIKE '%userrole%' OR
                        constraint_name LIKE '%serviceaccount%' OR
                        constraint_name LIKE '%organizationcontext%'
                    )
                ) LOOP
                    EXECUTE 'ALTER TABLE ' || r.table_name || ' DROP CONSTRAINT IF EXISTS ' || r.constraint_name;
                END LOOP;
            END $$;
            """,
            reverse_sql="-- Foreign key constraints would need to be recreated"
        ),
    ]
