-- SciCom CX central database (platform admins, servers, tenants, audit).
CREATE DATABASE scicomcx_central;

-- Tenant databases are created by SciCom CX itself (managed tenants).
-- This one is only for trying "Connect an existing database" in the UI.
CREATE USER external_user WITH PASSWORD 'external_pass';
CREATE DATABASE external_demo OWNER external_user;
REVOKE CONNECT ON DATABASE external_demo FROM PUBLIC;
