-- Least-privilege setup for Gatekeeper. Run once as a superuser with:
--   psql -v ON_ERROR_STOP=1 -v owner_pw=... -v app_pw=... -f db-roles.sql
--
-- gatekeeper_owner: owns the database, runs migrations (the `migrate` command). Not a superuser.
-- gatekeeper_app:   used by the running service. Data access only: no DDL, cannot create objects.
-- citext is a trusted extension (PostgreSQL 13+), so the non-superuser database owner may create it.

CREATE ROLE gatekeeper_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE gatekeeper_app   LOGIN PASSWORD :'app_pw'   NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE gatekeeper OWNER gatekeeper_owner;

\connect gatekeeper

REVOKE ALL ON DATABASE gatekeeper FROM PUBLIC;
GRANT CONNECT ON DATABASE gatekeeper TO gatekeeper_app;

ALTER SCHEMA public OWNER TO gatekeeper_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO gatekeeper_app;

-- Tables created later by the owner's migrations are automatically usable by the app role.
ALTER DEFAULT PRIVILEGES FOR ROLE gatekeeper_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO gatekeeper_app;
