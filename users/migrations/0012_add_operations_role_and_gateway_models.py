# Generated migration for Afyaflow GraphQL Gateway compliance

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0011_enhance_existing_models_with_client_role_context'),
    ]

    operations = [
        # Add OPERATIONS role to UserRole choices
        migrations.RunSQL(
            sql=[
                "ALTER TABLE users_userrole DROP CONSTRAINT IF EXISTS users_userrole_name_check;",
                "ALTER TABLE users_userrole ADD CONSTRAINT users_userrole_name_check CHECK (name IN ('PATIENT', 'PROVIDER', 'ADMIN', 'OPERATIONS'));",
            ],
            reverse_sql=[
                "ALTER TABLE users_userrole DROP CONSTRAINT IF EXISTS users_userrole_name_check;",
                "ALTER TABLE users_userrole ADD CONSTRAINT users_userrole_name_check CHECK (name IN ('PATIENT', 'PROVIDER', 'ADMIN'));",
            ]
        ),
        
        # Insert OPERATIONS role with default permissions
        migrations.RunSQL(
            sql=[
                """
                INSERT INTO users_userrole (name, description, permissions, is_active, created_at, updated_at)
                VALUES (
                    'OPERATIONS',
                    'Operations and system administration role with cross-tenant access',
                    '["view_all_users", "view_system_logs", "manage_system_settings", "access_admin_interface", "cross_tenant_access", "system_maintenance", "technical_support", "service_account_management", "global_monitoring"]',
                    true,
                    NOW(),
                    NOW()
                ) ON CONFLICT (name) DO NOTHING;
                """
            ],
            reverse_sql=[
                "DELETE FROM users_userrole WHERE name = 'OPERATIONS';"
            ]
        ),
        
        # Create ServiceAccount model
        migrations.CreateModel(
            name='ServiceAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('service_id', models.CharField(help_text='Unique service identifier (e.g., billing-svc-123abc)', max_length=100, unique=True)),
                ('service_type', models.CharField(help_text='Type of service (e.g., internal-billing, internal-patients)', max_length=50)),
                ('permissions', models.JSONField(default=list, help_text="List of permissions for this service (e.g., ['read:billing', 'write:billing'])")),
                ('is_active', models.BooleanField(default=True, help_text='Whether this service account is currently active')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'service account',
                'verbose_name_plural': 'service accounts',
                'ordering': ['service_id'],
            },
        ),
        
        # Create OrganizationContext model
        migrations.CreateModel(
            name='OrganizationContext',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization_id', models.UUIDField(help_text='Primary organization identifier')),
                ('branch_id', models.UUIDField(blank=True, help_text='Branch identifier within the organization', null=True)),
                ('cluster_id', models.UUIDField(blank=True, help_text='Cluster identifier for regional grouping', null=True)),
                ('subscribed_services', models.JSONField(default=list, help_text='List of services this organization has access to')),
                ('organization_permissions', models.JSONField(default=dict, help_text='Organization-specific permissions mapping')),
                ('is_active', models.BooleanField(default=True, help_text='Whether this organization context is active')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'organization context',
                'verbose_name_plural': 'organization contexts',
                'ordering': ['organization_id', 'branch_id', 'cluster_id'],
            },
        ),
        
        # Add migration tracking fields to RegisteredClient
        migrations.AddField(
            model_name='registeredclient',
            name='supports_new_token_format',
            field=models.BooleanField(default=False, help_text='Whether this client supports the new gateway-compliant token format'),
        ),
        migrations.AddField(
            model_name='registeredclient',
            name='legacy_token_support_until',
            field=models.DateTimeField(blank=True, help_text='Date until which legacy tokens will be supported for this client', null=True),
        ),
        migrations.AddField(
            model_name='registeredclient',
            name='migration_status',
            field=models.CharField(
                choices=[('LEGACY', 'Legacy Only'), ('DUAL', 'Dual Support'), ('NEW', 'New Format Only')],
                default='LEGACY',
                help_text='Current migration status for this client',
                max_length=20
            ),
        ),
        
        # Add indexes for ServiceAccount
        migrations.RunSQL(
            sql=[
                "CREATE INDEX IF NOT EXISTS idx_serviceaccount_service_id ON users_serviceaccount(service_id);",
                "CREATE INDEX IF NOT EXISTS idx_serviceaccount_service_type ON users_serviceaccount(service_type);",
                "CREATE INDEX IF NOT EXISTS idx_serviceaccount_is_active ON users_serviceaccount(is_active);",
                "CREATE INDEX IF NOT EXISTS idx_serviceaccount_created_at ON users_serviceaccount(created_at);",
            ],
            reverse_sql=[
                "DROP INDEX IF EXISTS idx_serviceaccount_service_id;",
                "DROP INDEX IF EXISTS idx_serviceaccount_service_type;",
                "DROP INDEX IF EXISTS idx_serviceaccount_is_active;",
                "DROP INDEX IF EXISTS idx_serviceaccount_created_at;",
            ]
        ),
        
        # Add indexes for OrganizationContext
        migrations.RunSQL(
            sql=[
                "CREATE INDEX IF NOT EXISTS idx_orgcontext_organization_id ON users_organizationcontext(organization_id);",
                "CREATE INDEX IF NOT EXISTS idx_orgcontext_branch_id ON users_organizationcontext(branch_id);",
                "CREATE INDEX IF NOT EXISTS idx_orgcontext_cluster_id ON users_organizationcontext(cluster_id);",
                "CREATE INDEX IF NOT EXISTS idx_orgcontext_is_active ON users_organizationcontext(is_active);",
                "CREATE INDEX IF NOT EXISTS idx_orgcontext_created_at ON users_organizationcontext(created_at);",
            ],
            reverse_sql=[
                "DROP INDEX IF EXISTS idx_orgcontext_organization_id;",
                "DROP INDEX IF EXISTS idx_orgcontext_branch_id;",
                "DROP INDEX IF EXISTS idx_orgcontext_cluster_id;",
                "DROP INDEX IF EXISTS idx_orgcontext_is_active;",
                "DROP INDEX IF EXISTS idx_orgcontext_created_at;",
            ]
        ),
        
        # Add unique constraint for OrganizationContext
        migrations.RunSQL(
            sql=[
                "ALTER TABLE users_organizationcontext ADD CONSTRAINT unique_org_branch_cluster UNIQUE (organization_id, branch_id, cluster_id);",
            ],
            reverse_sql=[
                "ALTER TABLE users_organizationcontext DROP CONSTRAINT IF EXISTS unique_org_branch_cluster;",
            ]
        ),
        
        # Add constraint for migration status
        migrations.RunSQL(
            sql=[
                "ALTER TABLE users_registeredclient ADD CONSTRAINT migration_status_check CHECK (migration_status IN ('LEGACY', 'DUAL', 'NEW'));",
            ],
            reverse_sql=[
                "ALTER TABLE users_registeredclient DROP CONSTRAINT IF EXISTS migration_status_check;",
            ]
        ),
    ]
