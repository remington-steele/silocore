-- Create the database
CREATE DATABASE silocore 
    WITH ENCODING 'UTF8'
    LOCALE_PROVIDER 'icu'
    ICU_LOCALE 'und-x-icu'
    TEMPLATE template0;

\c silocore; 

-- Don't allow public access to the database
REVOKE ALL ON SCHEMA public FROM public;    

-- Create the admin role and change the owner of the database to the admin role
CREATE ROLE silocore_admin;
ALTER DATABASE silocore OWNER TO silocore_admin;
GRANT ALL PRIVILEGES ON DATABASE silocore TO silocore_admin;
GRANT ALL ON SCHEMA public TO silocore_admin;

-- Ensure public schema is owned by silocore_admin
ALTER SCHEMA public OWNER TO silocore_admin;

-- Create the app role and assign privileges
CREATE ROLE silocore_app;
ALTER ROLE silocore_app SET search_path TO public;
GRANT USAGE ON SCHEMA public TO silocore_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO silocore_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO silocore_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO silocore_app;
GRANT EXECUTE ON ALL PROCEDURES IN SCHEMA public TO silocore_app;
GRANT TRIGGER ON ALL TABLES IN SCHEMA public TO silocore_app;

-- Ensure app role has permissions on future objects
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA public 
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO silocore_app;
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA public 
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO silocore_app;
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA public 
    GRANT EXECUTE ON FUNCTIONS TO silocore_app;
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA public 
    GRANT TRIGGER ON TABLES TO silocore_app;

-- Create a read-only role and assign privileges
CREATE ROLE silocore_readonly;
ALTER ROLE silocore_readonly SET search_path TO public;
GRANT USAGE ON SCHEMA public TO silocore_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO silocore_readonly;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO silocore_readonly;

-- Ensure readonly role has permissions on future objects
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA public 
    GRANT SELECT ON TABLES TO silocore_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE silocore_admin IN SCHEMA public 
    GRANT SELECT ON SEQUENCES TO silocore_readonly;

-- Create the admin user and assign roles
CREATE USER silocore_admin_user WITH PASSWORD 'silocore';
GRANT silocore_admin TO silocore_admin_user;

CREATE USER silocore_app_user WITH PASSWORD 'silocore';
GRANT silocore_app TO silocore_app_user;

CREATE USER silocore_readonly_user WITH PASSWORD 'silocore';
GRANT silocore_readonly TO silocore_readonly_user;
