// Tenant databases are created by SciCom CX itself (managed tenants).
// This one is only for trying "Connect an existing database" in the UI
// (authSource = external_demo).
db.getSiblingDB('external_demo').createUser({
  user: 'external_user',
  pwd: 'external_pass',
  roles: [{ role: 'readWrite', db: 'external_demo' }],
});
