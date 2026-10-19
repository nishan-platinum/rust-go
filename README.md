# SciCom CX: multi-tenant platform (Go + Rust)

SciCom CX runs every client (**tenant**) as its own workspace on its **own subdomain** with its **own database**.
Each tenant can use PostgreSQL, MySQL, MariaDB or MongoDB. Platform admins create tenants from a dashboard, and the
platform creates the database, the DB user, the tables and the tenant's first admin, then brings the subdomain live.

```
                       ┌──────────── admin.scicomcx.localhost ──► Admin console (sidebar dashboard)
 Browser ──HTTP──► Go ─┤
                       └──────────── <tenant>.scicomcx.localhost ─► Tenant portal (login + workspace)
                       │
                       ├──gRPC──► Rust engine ──► one pool per tenant ──► PostgreSQL / MySQL / MariaDB / MongoDB
                       └──► Central DB: PostgreSQL "scicomcx_central"
                            (platform admins, database servers, tenants, portal sessions, audit log)
```

| Part | Language | Responsibility |
|---|---|---|
| `go-api/` | **Go** | Subdomain routing, admin console and tenant portals (Go templates + HTMX), tenant creation workflow, logins and sessions, tenant JWT API, central DB, isolation test |
| `rust-engine/` | **Rust** | Data plane for all 4 DB types: creates and drops tenant databases and users, one pool per tenant, tables, tenant users, claim markers |
| `proto/` | protobuf | The gRPC contract between Go and Rust |

## Run it

```bash
docker compose up -d --build
```

| What | URL | Login |
|---|---|---|
| Admin console | http://admin.scicomcx.localhost:8080 | `admin` / `admin12345` |
| Demo tenant portals | http://acme.scicomcx.localhost:8080 (also `hooli`, `globex`, `initech`, `umbrella`) | `admin@<tenant>.test` / `demo12345` |

`*.localhost` resolves to your own machine in Chrome, Edge and Firefox, so you don't need to edit DNS or the hosts
file. http://127.0.0.1:8080 also opens the admin console.

On first start SciCom CX registers 4 **database servers** (one per DB type) and creates 5 demo tenants through the
same workflow the UI uses:

| Tenant | DB type | Database (auto-created) |
|---|---|---|
| acme | PostgreSQL | `scx_acme` |
| hooli | PostgreSQL (same server as acme) | `scx_hooli` |
| globex | MySQL 8.4 | `scx_globex` |
| initech | MariaDB 11.4 | `scx_initech` |
| umbrella | MongoDB 8 | `scx_umbrella` |

## Creating a tenant (sidebar → **+ New tenant**)

1. **Workspace:** enter the name and subdomain. The subdomain is filled in from the name and checked live; reserved
   names such as `admin`, `www` and `api` are refused.
2. **Database:** pick PostgreSQL, MySQL, MariaDB or MongoDB, then choose how it is set up:
   - **Create it for me (managed):** on the type's default server, or one you pick. A database and a DB user named
     `scx_<subdomain>` are created with a random password, which is stored encrypted.
   - **Connect an existing database (external):** e.g. the client's own server. Each DB server has an
     `external_demo` database (user `external_user` / `external_pass`) for trying this out.
3. **Tenant admin:** enter the email, name and password. Leave the password empty to have one generated and shown
   once.

You then see a checklist (validate, create DB and user, register, create tables and claim, create admin, activate
subdomain) and a link to the live workspace. **If any step fails, everything done so far is rolled back.**

**Deleting a tenant** removes its registration and ends its sessions. For managed tenants you can also drop the
database and DB user; this requires typing the tenant id to confirm. External databases are never dropped.

## Workspace address: subdomain or the client's own domain

When creating a tenant, the admin picks the **workspace address** per client:

| Choice | Address | Live |
|---|---|---|
| Subdomain | `acme.scicomcx.localhost` | immediately |
| Client's own domain | `support.acme.com` (no subdomain) | once the client's DNS is verified |

The short **Tenant ID** (e.g. `acme`) is always required. It names the database (`scx_acme`) and becomes the
subdomain when that is switched on. On the tenant's **Domains** page domains can be added, verified, made primary
or removed, and the subdomain turned on or off. For example, to move a client from the subdomain to their own
domain: add the domain, verify it, then turn the subdomain off. A workspace always keeps at least one live address,
so turning off or removing the last one is refused. The first verified domain becomes primary, and console links
use it.

Adding a custom domain:

1. Enter it in the New tenant form, or later under **Tenants → Domains**.
2. The client creates the 2 DNS records shown on the page:
   - `CNAME support.acme.com → tenants.<BASE_DOMAIN>` points the domain to SciCom CX;
   - `TXT _scicomcx-challenge.support.acme.com → <code>` proves they own it.
3. Click **Verify**. The domain is only served after this. **Make primary** makes console links use it.
   **Remove** stops it immediately.

Local testing: with `DOMAIN_DEV_AUTOVERIFY=true` (set in `docker-compose.yml`, never in production), domains
ending in `.localhost` are verified without DNS. The demo seeds http://wayne-portal.localhost:8080 (wayne, own domain only;
login `admin@wayne.test` / `demo12345`). The other demo tenants use subdomains.

HTTPS in production: put a proxy with on-demand TLS (e.g. Caddy) in front and set its *ask* URL to
`http://go-api:8080/internal/tls-ask`. It returns 200 only for hosts SciCom CX serves (verified custom domains,
tenant subdomains, the console), so certificates are never issued for random domains.

```
{
  on_demand_tls { ask http://go-api:8080/internal/tls-ask }
}
https:// {
  tls { on_demand }
  reverse_proxy go-api:8080
}
```

## Where the data lives

| Data | Stored in |
|---|---|
| Platform admins, sessions, database servers (encrypted admin logins), tenant registry (encrypted DB logins), custom domains, audit log | `scicomcx_central` |
| Tenant portal sessions (each bound to its tenant) | `scicomcx_central` |
| **Tenant users** (bcrypt hashes), records and the ownership marker | **the tenant's own database** |

## Isolation guarantees

1. **Separate subdomains, separate cookies.** Portal cookies are host-only, so the browser never sends acme's cookie
   to globex. Even if it did, the server only accepts a session issued for the same tenant.
2. **Separate databases and DB users.** Each managed tenant gets its own database and least-privilege user
   (Postgres `REVOKE CONNECT ... FROM PUBLIC`).
3. **Claim marker.** The first tenant to provision a database claims it. The engine refuses to serve, or let another
   tenant connect to, a claimed database. Pointing a second tenant at it fails, and its creation is rolled back.
4. **One pool per tenant, versioned config.** Session state can't leak through shared pooled connections, and
   config changes swap pools safely under load.
5. **Tenant tokens** (`/api/v1/tenants/{id}/…`) are bound to one tenant and revocable via the token version.
6. **Encrypted secrets.** DB passwords use AES-256-GCM with the tenant or server name bound in. Session tokens are
   stored as hashes. Logins take the same time whether or not the user exists, and are rate-limited.

## Isolation test

Run it from the console (**Isolation test**) or from CI:

```bash
cd go-api && go run ./cmd/isotest -pass admin12345
```

It runs concurrent reads and writes against every tenant at once, with a hot pool swap halfway through. It checks
the in-database marker, pooled session state and row ownership, then runs the token checks, the admin-session checks
and the **subdomain** checks:

- a tenant's session doesn't work on another tenant's subdomain;
- an unknown subdomain returns 404;
- admin pages aren't reachable from a tenant host;
- admin and tenant cookies can't be swapped;
- the portal enforces CSRF.

Latest result: 6 tenants on 4 DB types, 0 leaks, 120 of 120 checks passed.

## Configuration

| Variable | Default / note |
|---|---|
| `BASE_DOMAIN` | `scicomcx.localhost`; tenants are served at `<id>.BASE_DOMAIN` and the console at `admin.BASE_DOMAIN` |
| `PUBLIC_SCHEME` / `PUBLIC_PORT` | `http` / the listen port; used to build workspace links |
| `CONTROL_DB_URL` | required (`…/scicomcx_central`) |
| `ENGINE_ADDR`, `ENGINE_INTERNAL_TOKEN` | Go ↔ Rust address and shared secret (at least 16 characters) |
| `MASTER_KEY` | required, 32 bytes base64; encrypts DB passwords in the central DB |
| `JWT_SECRET` | required, at least 32 bytes |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | the platform admin created on first start |
| `DOMAIN_DEV_AUTOVERIFY` | `false`; `true` verifies `*.localhost` custom domains without DNS (local testing only) |
| `SEED_FILE` | `seed/tenants.json`: database servers plus demo tenants, used on first start only |
| `COOKIE_SECURE` | `true`; set to `false` only for plain-HTTP local dev |

### Going to a real domain

1. Point a wildcard DNS record `*.scicomcx.example.com` (and `scicomcx.example.com`) at the server.
2. Set `BASE_DOMAIN=scicomcx.example.com`, `PUBLIC_SCHEME=https`, `PUBLIC_PORT=` and `COOKIE_SECURE=true`.
3. Terminate TLS with a wildcard certificate in a reverse proxy, and forward the original `Host` header.

## Production next steps

- mTLS between Go and Rust (see the `TODO(prod)` in `go-api/internal/engine`).
- Keep `MASTER_KEY`, `JWT_SECRET` and the server admin passwords in Vault or a KMS, and support key rotation.
- Use database-server admin accounts with only `CREATEDB`/`CREATEROLE` (not superuser).
- With many tenants: evict idle tenant pools, put PgBouncer in front of Postgres, and push registry changes to all API
  replicas with `LISTEN/NOTIFY`.
- Add password reset and SSO for tenant users.

The credentials in `docker-compose.yml`, `deploy/init` and `go-api/seed` are for local testing only.
