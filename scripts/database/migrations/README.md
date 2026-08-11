# Database migrations (consolidated)

All historical migrations were **consolidated into `schema.sql`**; the original per-feature migration files have been removed. There is no migration runner — schema changes are appended directly to `schema.sql`.

On a **fresh development deployment**, all database initialization is done by:

1. **PostgreSQL init (fresh volume only)**  
   - **01-schema.sql** ← `scripts/database/schema.sql` (full schema + built-in data + permission reconciliation)  
   - **02-seed.sql** ← `scripts/database/seed.sql`

2. **Session-init (every run)**  
   - `scripts/apply_core_seed.sh` (idempotent framework/template seed)  
   - **04-ensure-licenses.sql** (ensures all tenants have Best Practices framework licenses)

No other migration scripts run at init. There are no pending migrations in this folder; all schema and seed changes are maintained in `schema.sql` and `seed.sql`.
