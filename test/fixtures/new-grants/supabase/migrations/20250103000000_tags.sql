create table public.tags (id serial primary key, name text not null, owner_id uuid not null references auth.users (id));
alter table public.tags enable row level security;
create policy "own tags" on public.tags for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());
