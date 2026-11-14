# Postgres audit sink: roles and permissions

The triggers created by tollkeeper reject `UPDATE`, `DELETE` and `TRUNCATE` and validate every `INSERT`, but a table owner can drop triggers. Run migrations as an owner role, and run the gateway as a role that can only append and read.

```sql
CREATE ROLE tollkeeper_owner NOLOGIN;
CREATE ROLE tollkeeper_gateway LOGIN PASSWORD 'change-me';
CREATE ROLE tollkeeper_auditor LOGIN PASSWORD 'change-me';

CREATE SCHEMA tollkeeper AUTHORIZATION tollkeeper_owner;
```

Apply the schema once as the owner:

```bash
psql "postgres://tollkeeper_owner@db/app?search_path=tollkeeper" -f internal/audit/pgsink/schema.sql
```

Then grant the minimum:

```sql
GRANT USAGE ON SCHEMA tollkeeper TO tollkeeper_gateway, tollkeeper_auditor;
GRANT INSERT, SELECT ON tollkeeper.tollkeeper_audit TO tollkeeper_gateway;
GRANT SELECT ON tollkeeper.tollkeeper_audit TO tollkeeper_auditor;
REVOKE UPDATE, DELETE, TRUNCATE ON tollkeeper.tollkeeper_audit FROM PUBLIC, tollkeeper_gateway, tollkeeper_auditor;
```

Set `audit.postgres.migrate: false` so the gateway only connects and never runs DDL. The default (`true`) suits development, where the gateway role owns the table: the migration is idempotent and guarded by an advisory lock, so concurrent replicas never race.

Auditors verify a chain without the gateway:

```bash
tollkeeper audit verify --postgres "postgres://tollkeeper_auditor@db/app?search_path=tollkeeper" --chain-id gw-1 --pubkey audit-ed25519.pub
```
