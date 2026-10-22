-- One failure inside BEGIN/COMMIT mustn't take the whole block with it.
begin;
create table drafts (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table drafts enable row level security;
create policy "own drafts" on drafts for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
alter table drafts add column legacy_ref uuid references old_drafts (id);
create index drafts_user_idx on drafts (user_id);
commit;

do $a2$
begin
  alter publication supabase_realtime add table public.drafts;
exception when duplicate_object then null;
end
$a2$;
