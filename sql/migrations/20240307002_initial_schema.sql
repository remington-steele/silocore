-- Important!  Do this to ensure tables have the correct owner and permissions!
SET ROLE silocore_admin;

-- Create a table for our tenants
CREATE TABLE tenant (
    tenant_id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(64) NOT NULL CHECK (status IN ('active', 'suspended', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create a table for users of the platform
CREATE TABLE usr (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE CHECK (email <> ''),
    password_hash VARCHAR(255) NOT NULL CHECK (password_hash <> ''),
    first_name VARCHAR(255) NOT NULL CHECK (first_name <> ''),
    last_name VARCHAR(255) NOT NULL CHECK (last_name <> ''),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create a table for system roles
CREATE TABLE role (
    role_id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT NOT NULL
);

-- Create a table to link users to roles at the platform level
CREATE TABLE user_role (
    user_id INTEGER NOT NULL REFERENCES usr(user_id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES role(role_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_role_role_id_idx ON user_role(role_id);

-- Create a table to map users to tenants
CREATE TABLE tenant_member (
    tenant_id INTEGER NOT NULL REFERENCES tenant(tenant_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES usr(user_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX tenant_member_user_id_idx ON tenant_member(user_id);

-- Create a table to map users to tenants and roles
CREATE TABLE tenant_role (
    tenant_id INTEGER NOT NULL REFERENCES tenant(tenant_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES usr(user_id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES role(role_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id, role_id)
);
CREATE INDEX tenant_role_user_id_idx ON tenant_role(user_id);
CREATE INDEX tenant_role_role_id_idx ON tenant_role(role_id);

-- Insert default roles
INSERT INTO role (name, description) VALUES
    ('ADMIN', 'Platform administrators with full access to all features and data'),
    ('INTERNAL', 'Internal SAAS platform access to reports, analytics, etc'),
    ('TENANT_SUPER', 'A tenant superuser who can perform administrative functions within a tenant');

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers to automatically update the updated_at column
CREATE TRIGGER update_tenant_updated_at
BEFORE UPDATE ON tenant
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER update_usr_updated_at
BEFORE UPDATE ON usr
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();