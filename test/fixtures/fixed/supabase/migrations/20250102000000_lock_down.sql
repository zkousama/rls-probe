-- orders: turn row-level security on and give each user their own rows
alter table public.orders enable row level security;
create policy "own orders" on public.orders for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- messages: only the sender reads and edits their messages
drop policy "auth read" on public.messages;
drop policy "auth write" on public.messages;
create policy "own read" on public.messages for select to authenticated using (sender_id = auth.uid());
create policy "own write" on public.messages for update to authenticated using (sender_id = auth.uid()) with check (sender_id = auth.uid());

-- profiles: each user reads their own profile
drop policy "Profiles are viewable by everyone" on public.profiles;
create policy "own profile" on public.profiles for select to authenticated using (id = auth.uid());

-- the delete function checks the caller, and visitors can't run it
create or replace function public.delete_order(order_id uuid) returns void language sql security definer set search_path = public as $$
  delete from public.orders where id = order_id and user_id = auth.uid()
$$;
revoke execute on function public.delete_order(uuid) from anon, public;

-- the totals view respects the rules on orders
alter view public.order_totals set (security_invoker = true);
