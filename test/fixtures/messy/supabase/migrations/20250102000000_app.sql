-- ---------------------------------------------------------------------------
-- Note 0: the kind of long header pg_dump and AI builders write.
-- Note 1: the kind of long header pg_dump and AI builders write.
-- Note 2: the kind of long header pg_dump and AI builders write.
-- Note 3: the kind of long header pg_dump and AI builders write.
-- Note 4: the kind of long header pg_dump and AI builders write.
-- Note 5: the kind of long header pg_dump and AI builders write.
-- Note 6: the kind of long header pg_dump and AI builders write.
-- Note 7: the kind of long header pg_dump and AI builders write.
-- Note 8: the kind of long header pg_dump and AI builders write.
-- Note 9: the kind of long header pg_dump and AI builders write.
-- Note 10: the kind of long header pg_dump and AI builders write.
-- Note 11: the kind of long header pg_dump and AI builders write.
-- Note 12: the kind of long header pg_dump and AI builders write.
-- Note 13: the kind of long header pg_dump and AI builders write.
-- Note 14: the kind of long header pg_dump and AI builders write.
-- Note 15: the kind of long header pg_dump and AI builders write.
-- Note 16: the kind of long header pg_dump and AI builders write.
-- Note 17: the kind of long header pg_dump and AI builders write.
-- Note 18: the kind of long header pg_dump and AI builders write.
-- Note 19: the kind of long header pg_dump and AI builders write.
-- Note 20: the kind of long header pg_dump and AI builders write.
-- Note 21: the kind of long header pg_dump and AI builders write.
-- Note 22: the kind of long header pg_dump and AI builders write.
-- Note 23: the kind of long header pg_dump and AI builders write.
-- Note 24: the kind of long header pg_dump and AI builders write.
-- Note 25: the kind of long header pg_dump and AI builders write.
-- Note 26: the kind of long header pg_dump and AI builders write.
-- Note 27: the kind of long header pg_dump and AI builders write.
-- Note 28: the kind of long header pg_dump and AI builders write.
-- Note 29: the kind of long header pg_dump and AI builders write.
-- Note 30: the kind of long header pg_dump and AI builders write.
-- Note 31: the kind of long header pg_dump and AI builders write.
-- Note 32: the kind of long header pg_dump and AI builders write.
-- Note 33: the kind of long header pg_dump and AI builders write.
-- Note 34: the kind of long header pg_dump and AI builders write.
-- Note 35: the kind of long header pg_dump and AI builders write.
-- Note 36: the kind of long header pg_dump and AI builders write.
-- Note 37: the kind of long header pg_dump and AI builders write.
-- Note 38: the kind of long header pg_dump and AI builders write.
-- Note 39: the kind of long header pg_dump and AI builders write.
-- ---------------------------------------------------------------------------

-- Unqualified names: these fail if the dump's empty search_path leaked into this file.
create table organizations (id uuid primary key default gen_random_uuid(), name text not null);
create table organization_members (
  organization_id uuid not null references organizations (id),
  user_id uuid not null references auth.users (id),
  role text not null default 'owner',
  primary key (organization_id, user_id)
);
alter table organizations enable row level security;
alter table organization_members enable row level security;
create policy "members read their org" on organizations for select to authenticated
  using (exists (select 1 from organization_members m where m.organization_id = organizations.id and m.user_id = auth.uid()));
create policy "owners edit their org" on organizations for update to authenticated
  using (exists (select 1 from organization_members m where m.organization_id = organizations.id and m.user_id = auth.uid() and m.role = 'owner'));
create policy "own memberships" on organization_members for select to authenticated using (user_id = auth.uid());

-- uuid_generate_v4() without create extension, a LIKE check, and a pgvector column.
create table photos (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid references auth.users (id),
  storage_path text not null check (storage_path like 'photos/%'),
  embedding vector(3)
);
alter table photos enable row level security;
create policy "anyone uploads" on photos for insert to anon, authenticated with check (true);
create policy "own photos" on photos for select to authenticated using (user_id = auth.uid());
create index photos_embedding_idx on photos using hnsw (embedding vector_cosine_ops);
create function match_photos(query extensions.vector, k int) returns setof photos language sql stable as $$
  select * from photos order by embedding <=> query limit k
$$;

-- Readable by visitors, emails included. Hidden if "row_security = off" leaked.
create table posts (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text not null, email text);
alter table posts enable row level security;
create policy "everyone reads posts" on posts for select using (true);

-- A global settings row: updated_by records who touched it, not whose it is.
create table app_settings (id text primary key default 'global', theme text not null default 'light', updated_by uuid references auth.users (id));
alter table app_settings enable row level security;
create policy "signed-in users read settings" on app_settings for select to authenticated using (true);
create policy "signed-in users edit settings" on app_settings for update to authenticated using (true);

-- Row-level security off, visitors revoked: every signed-in user still reaches every row.
create table server_notes (id bigint generated always as identity primary key, user_id uuid not null references auth.users (id), body text not null);
revoke all on server_notes from anon;

-- Points at a table made in the dashboard, which no migration creates.
create table reports (id uuid primary key default gen_random_uuid(), legacy_id uuid references legacy_table (id), user_id uuid references auth.users (id));

-- A sign-up trigger writing to a table that doesn't exist.
create function handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.welcome_emails (user_id) values (new.id);
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();
