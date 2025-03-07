
-- Create a table for our tenants
CREATE TABLE core.tenant (
    tenant_id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(64) NOT NULL CHECK (status IN ('active', 'suspended', 'disabled')),
    tier VARCHAR(64) NOT NULL CHECK (tier IN ('gold', 'silver', 'bronze')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create a table for users of the platform
CREATE TABLE core.usr (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    given_name VARCHAR(255) NOT NULL CHECK (given_name <> ''),
    family_name VARCHAR(255) NOT NULL CHECK (family_name <> ''),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create a table for system roles
CREATE TABLE core.role (
    role_id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create a table to link users to roles at the platform level
CREATE TABLE core.user_role (
    user_id INTEGER NOT NULL REFERENCES core.usr(user_id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES core.role(role_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- Create a table to map users to tenants
CREATE TABLE core.tenant_member (
    tenant_id INTEGER NOT NULL REFERENCES core.tenant(tenant_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES core.usr(user_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);

-- Create a table to map users to tenants and roles
CREATE TABLE core.tenant_role (
    tenant_id INTEGER NOT NULL REFERENCES core.tenant(tenant_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES core.usr(user_id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES core.role(role_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id, role_id)
);

-- Insert default roles
INSERT INTO core.role (name, description) VALUES
    ('ADMIN', 'Platform administrators with full access to all features and data'),
    ('INTERNAL', 'Internal SAAS platform access to reports, analytics, etc'),
    ('TENANT_SUPER', 'A tenant superuser who can perform administrative functions within a tenant');

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION core.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers to automatically update the updated_at column
CREATE TRIGGER update_tenant_updated_at
BEFORE UPDATE ON core.tenant
FOR EACH ROW
EXECUTE FUNCTION core.update_updated_at_column();

CREATE TRIGGER update_usr_updated_at
BEFORE UPDATE ON core.usr
FOR EACH ROW
EXECUTE FUNCTION core.update_updated_at_column();

CREATE TRIGGER update_role_updated_at
BEFORE UPDATE ON core.role
FOR EACH ROW
EXECUTE FUNCTION core.update_updated_at_column(); 