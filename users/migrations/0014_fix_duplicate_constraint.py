# Generated migration to fix duplicate constraint issue

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0013_organizationcontext_users_organ_organiz_87bea3_idx_and_more'),
    ]

    operations = [
        # This migration handles the duplicate constraint issue
        # by checking if the constraint exists before creating it
        migrations.RunSQL(
            sql="""
            DO $$
            BEGIN
                -- Check if constraint exists and drop it if it does
                IF EXISTS (
                    SELECT 1 FROM pg_constraint 
                    WHERE conname = 'unique_org_branch_cluster'
                ) THEN
                    ALTER TABLE users_organizationcontext 
                    DROP CONSTRAINT unique_org_branch_cluster;
                END IF;
                
                -- Recreate the constraint
                ALTER TABLE users_organizationcontext 
                ADD CONSTRAINT unique_org_branch_cluster 
                UNIQUE (organization_id, branch_id);
            END $$;
            """,
            reverse_sql="""
            ALTER TABLE users_organizationcontext 
            DROP CONSTRAINT IF EXISTS unique_org_branch_cluster;
            """
        ),
    ]
