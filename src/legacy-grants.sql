-- Supabase's default before the 2026 grants change: anon and authenticated can
-- use every table in public, and row-level security alone decides which rows.
alter default privileges in schema public grant all on tables to anon, authenticated;
alter default privileges in schema public grant all on sequences to anon, authenticated;
