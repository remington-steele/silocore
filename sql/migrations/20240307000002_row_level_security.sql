-- Create a function to get the current tenant context
CREATE OR REPLACE FUNCTION core.current_tenant_id()
RETURNS INTEGER AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_tenant_id', TRUE), '')::INTEGER;
END;
$$ LANGUAGE plpgsql;

-- Enable Row Level Security on tenant table
ALTER TABLE core.tenant ENABLE ROW LEVEL SECURITY;

-- Create RLS policy for tenant table
-- This policy allows access to rows where the tenant_id matches the app.current_tenant_id setting
-- or when the app.current_tenant_id is not set (for admin operations)
CREATE POLICY tenant_isolation_policy ON core.tenant
    USING (
        tenant_id = core.current_tenant_id() 
        OR 
        core.current_tenant_id() IS NULL
    );

-- Enable Row Level Security on tenant_member table
ALTER TABLE core.tenant_member ENABLE ROW LEVEL SECURITY;

-- Create RLS policy for tenant_member table
CREATE POLICY tenant_member_isolation_policy ON core.tenant_member
    USING (
        tenant_id = core.current_tenant_id() 
        OR 
        core.current_tenant_id() IS NULL
    );

-- Enable Row Level Security on tenant_role table
ALTER TABLE core.tenant_role ENABLE ROW LEVEL SECURITY;

-- Create RLS policy for tenant_role table
CREATE POLICY tenant_role_isolation_policy ON core.tenant_role
    USING (
        tenant_id = core.current_tenant_id() 
        OR 
        core.current_tenant_id() IS NULL
    );

-- Create a function to set the current tenant context
CREATE OR REPLACE FUNCTION core.set_tenant_context(p_tenant_id INTEGER)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant_id', p_tenant_id::TEXT, FALSE);
END;
$$ LANGUAGE plpgsql;

-- Create a function to clear the tenant context (for admin operations)
CREATE OR REPLACE FUNCTION core.clear_tenant_context()
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant_id', '', FALSE);
END;
$$ LANGUAGE plpgsql; 