-- Rollback script for migration 0012_add_operations_role_and_gateway_models
-- Run this script to manually rollback the migration if needed

BEGIN;

-- Remove migration tracking fields from RegisteredClient
ALTER TABLE users_registeredclient DROP CONSTRAINT IF EXISTS migration_status_check;
ALTER TABLE users_registeredclient DROP COLUMN IF EXISTS migration_status;
ALTER TABLE users_registeredclient DROP COLUMN IF EXISTS legacy_token_support_until;
ALTER TABLE users_registeredclient DROP COLUMN IF EXISTS supports_new_token_format;

-- Remove OrganizationContext constraints and indexes
ALTER TABLE users_organizationcontext DROP CONSTRAINT IF EXISTS unique_org_branch_cluster;
DROP INDEX IF EXISTS idx_orgcontext_created_at;
DROP INDEX IF EXISTS idx_orgcontext_is_active;
DROP INDEX IF EXISTS idx_orgcontext_cluster_id;
DROP INDEX IF EXISTS idx_orgcontext_branch_id;
DROP INDEX IF EXISTS idx_orgcontext_organization_id;

-- Remove ServiceAccount indexes
DROP INDEX IF EXISTS idx_serviceaccount_created_at;
DROP INDEX IF EXISTS idx_serviceaccount_is_active;
DROP INDEX IF EXISTS idx_serviceaccount_service_type;
DROP INDEX IF EXISTS idx_serviceaccount_service_id;

-- Drop new models
DROP TABLE IF EXISTS users_organizationcontext;
DROP TABLE IF EXISTS users_serviceaccount;

-- Remove OPERATIONS role
DELETE FROM users_userrole WHERE name = 'OPERATIONS';

-- Restore original UserRole constraint
ALTER TABLE users_userrole DROP CONSTRAINT IF EXISTS users_userrole_name_check;
ALTER TABLE users_userrole ADD CONSTRAINT users_userrole_name_check 
CHECK (name IN ('PATIENT', 'PROVIDER', 'ADMIN'));

COMMIT;

-- Verification queries (run these to verify rollback was successful)
-- SELECT name FROM users_userrole WHERE name = 'OPERATIONS'; -- Should return no rows
-- SELECT table_name FROM information_schema.tables WHERE table_name IN ('users_serviceaccount', 'users_organizationcontext'); -- Should return no rows
-- SELECT column_name FROM information_schema.columns WHERE table_name = 'users_registeredclient' AND column_name IN ('supports_new_token_format', 'legacy_token_support_until', 'migration_status'); -- Should return no rows
