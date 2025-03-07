-- Create the database
CREATE DATABASE silocore 
    WITH ENCODING 'UTF8'
    LOCALE_PROVIDER 'icu'
    ICU_LOCALE 'und-x-icu'
    TEMPLATE template0;

-- Create the admin role and change the owner of the database to the admin role
CREATE ROLE silocore_admin;

ALTER DATABASE silocore OWNER TO silocore_admin;

GRANT ALL PRIVILEGES ON DATABASE silocore TO silocore_admin;

-- Create the core schema
CREATE SCHEMA core AUTHORIZATION silocore_admin;

-- Create the app role and assign privileges
CREATE ROLE silocore_app;
ALTER ROLE silocore_app SET search_path TO core, public;
GRANT USAGE ON SCHEMA core TO silocore_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core TO silocore_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA core TO silocore_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA core TO silocore_app;
GRANT EXECUTE ON ALL PROCEDURES IN SCHEMA core TO silocore_app;
GRANT TRIGGER ON ALL TABLES IN SCHEMA core TO silocore_app;

-- Ensure app role has permissions on future objects
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA core 
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO silocore_app;
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA core 
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO silocore_app;
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA core 
    GRANT EXECUTE ON FUNCTIONS TO silocore_app;
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA core 
    GRANT TRIGGER ON TABLES TO silocore_app;

-- Create a read only role and assign privileges
CREATE ROLE silocore_readonly;
ALTER ROLE silocore_readonly SET search_path TO core, public;
GRANT USAGE ON SCHEMA core TO silocore_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA core TO silocore_readonly;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA core TO silocore_readonly;

-- Ensure readonly role has permissions on future objects
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA core 
    GRANT SELECT ON TABLES TO silocore_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA core 
    GRANT SELECT ON SEQUENCES TO silocore_readonly;

-- Create the admin user and assign roles
CREATE USER silocore_admin_user WITH PASSWORD 'silocore';
GRANT silocore_admin TO silocore_admin_user;

CREATE USER silocore_app_user WITH PASSWORD 'silocore';
GRANT silocore_app TO silocore_app_user;

CREATE USER silocore_readonly_user WITH PASSWORD 'silocore';
GRANT silocore_readonly TO silocore_readonly_user;