-- Views for scripts/compare-view-grants-with-supabase.mjs, run after test/fixtures/new-grants'
-- migrations: one on a view that follows the tables' rules, and one that runs as its owner.
create view public.my_order_totals with (security_invoker = true) as select user_id, total from public.order_totals;
create view public.all_order_totals as select user_id, sum(total) as total from public.orders group by user_id;
