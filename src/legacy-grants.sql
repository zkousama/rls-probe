-- Supabase's default before the 2026 grants change: anon, authenticated and
-- service_role can use every table in public, and row-level security alone
-- decides which rows the first two reach.
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
