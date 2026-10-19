-- Tenant databases are created by SciCom CX itself (managed tenants).
-- This one is only for trying "Connect an existing database" in the UI.
CREATE DATABASE external_demo;
CREATE USER 'external_user'@'%' IDENTIFIED BY 'external_pass';
GRANT ALL PRIVILEGES ON external_demo.* TO 'external_user'@'%';
