SET ROLE silocore_admin;

-- Create a function to get the current tenant context
CREATE OR REPLACE FUNCTION tenant_context()
RETURNS INTEGER AS $$
BEGIN
    RETURN NULLIF(current_setting('core.tenant_context', TRUE), '')::INTEGER;
END;
$$ LANGUAGE plpgsql;

-- Enable Row Level Security on tenant table
ALTER TABLE tenant ENABLE ROW LEVEL SECURITY;

-- Create RLS policy for tenant table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'tenant' AND policyname = 'tenant_isolation_policy'
    ) THEN
        CREATE POLICY tenant_isolation_policy ON tenant
        USING (
            tenant_id = tenant_context() 
            OR 
            tenant_context() IS NULL
        );
    END IF;
END
$$;

-- Enable Row Level Security on tenant_member table
ALTER TABLE tenant_member ENABLE ROW LEVEL SECURITY;

-- Create RLS policy for tenant_member table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'tenant_member' AND policyname = 'tenant_member_isolation_policy'
    ) THEN
        CREATE POLICY tenant_member_isolation_policy ON tenant_member
        USING (
            tenant_id = tenant_context() 
            OR 
            tenant_context() IS NULL
        );
    END IF;
END
$$;

-- Enable Row Level Security on tenant_role table
ALTER TABLE tenant_role ENABLE ROW LEVEL SECURITY;

-- Create RLS policy for tenant_role table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'tenant_role' AND policyname = 'tenant_role_isolation_policy'
    ) THEN
        CREATE POLICY tenant_role_isolation_policy ON tenant_role
        USING (
            tenant_id = tenant_context() 
            OR 
            tenant_context() IS NULL
        );
    END IF;
END
$$;

-- Create a function to set the current tenant context
CREATE OR REPLACE FUNCTION set_tenant_context(tenant_id INTEGER)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('core.tenant_context', tenant_id::TEXT, FALSE);
END;
$$ LANGUAGE plpgsql;

-- Create a function to clear the tenant context (for admin operations)
CREATE OR REPLACE FUNCTION clear_tenant_context()
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('core.tenant_context', '', FALSE);
END;
$$ LANGUAGE plpgsql; 