-- The parts of a Supabase database that migrations and access rules lean on,
-- recreated so the migrations run in an in-memory Postgres.

create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;
create role authenticator nologin noinherit;
create role supabase_admin nologin;
create role supabase_auth_admin nologin;
create role supabase_storage_admin nologin;
create role dashboard_user nologin;
create role pgbouncer nologin;
grant anon, authenticated, service_role to authenticator;

create schema if not exists extensions;
create schema if not exists auth;
create schema if not exists storage;
create schema if not exists realtime;
create schema if not exists graphql_public;
create schema if not exists supabase_functions;
create schema if not exists net;
create schema if not exists cron;
create schema if not exists vault;

grant usage on schema public, extensions, auth, storage, graphql_public, realtime to anon, authenticated, service_role;

-- Every Supabase project has these two, and migrations call uuid_generate_v4(),
-- gen_random_bytes() or digest() without creating them.
create extension if not exists pgcrypto with schema extensions;
create extension if not exists "uuid-ossp" with schema extensions;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
-- Table and sequence grants for anon, authenticated and service_role are in
-- legacy-grants.js: Supabase's old default, which new tables stop getting with
-- the 2026 grants change.

create table auth.users (
  instance_id uuid,
  id uuid primary key,
  aud varchar(255),
  role varchar(255),
  email varchar(255) unique,
  encrypted_password varchar(255),
  email_confirmed_at timestamptz,
  invited_at timestamptz,
  confirmation_token varchar(255),
  recovery_token varchar(255),
  last_sign_in_at timestamptz,
  raw_app_meta_data jsonb default '{}'::jsonb,
  raw_user_meta_data jsonb default '{}'::jsonb,
  is_super_admin boolean,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  phone text unique,
  phone_confirmed_at timestamptz,
  confirmed_at timestamptz,
  banned_until timestamptz,
  deleted_at timestamptz,
  is_sso_user boolean not null default false,
  is_anonymous boolean not null default false
);
create table auth.identities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  provider text,
  identity_data jsonb,
  created_at timestamptz default now()
);
grant select on auth.users to service_role;

create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')
  )::jsonb
$$;
create function auth.uid() returns uuid language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;
create function auth.role() returns text language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;
create function auth.email() returns text language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;
grant execute on function auth.jwt(), auth.uid(), auth.role(), auth.email() to anon, authenticated, service_role;
create table auth.sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz default now(),
  updated_at timestamptz,
  not_after timestamptz,
  aal text
);
create table auth.refresh_tokens (
  id bigserial primary key,
  token varchar(255),
  user_id varchar(255),
  revoked boolean,
  created_at timestamptz,
  updated_at timestamptz,
  parent varchar(255),
  session_id uuid references auth.sessions (id) on delete cascade
);

create table storage.buckets (
  id text primary key,
  name text not null unique,
  owner uuid,
  public boolean default false,
  avif_autodetection boolean default false,
  file_size_limit bigint,
  allowed_mime_types text[],
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create table storage.objects (
  id uuid primary key default gen_random_uuid(),
  bucket_id text references storage.buckets (id),
  name text,
  owner uuid,
  owner_id text,
  metadata jsonb,
  path_tokens text[] generated always as (string_to_array(name, '/')) stored,
  version text,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  last_accessed_at timestamptz default now()
);
alter table storage.objects enable row level security;
alter table storage.buckets enable row level security;
grant all on storage.objects, storage.buckets to anon, authenticated, service_role;
create function storage.foldername(name text) returns text[] language sql immutable as $$
  select (string_to_array(name, '/'))[1:array_length(string_to_array(name, '/'), 1) - 1]
$$;
create function storage.filename(name text) returns text language sql immutable as $$
  select (string_to_array(name, '/'))[array_length(string_to_array(name, '/'), 1)]
$$;
create function storage.extension(name text) returns text language sql immutable as $$
  select reverse(split_part(reverse(name), '.', 1))
$$;
grant execute on all functions in schema storage to anon, authenticated, service_role;

-- Realtime: the publication tables are added to, and the table whose policies
-- decide who may join a private channel.
create publication supabase_realtime;
create table realtime.messages (
  id uuid not null default gen_random_uuid(),
  topic text not null,
  extension text not null,
  payload jsonb,
  event text,
  private boolean default false,
  updated_at timestamp not null default now(),
  inserted_at timestamp not null default now(),
  primary key (id, inserted_at)
);
alter table realtime.messages enable row level security;
create table realtime.subscription (
  id bigint generated always as identity primary key,
  subscription_id uuid not null,
  entity regclass not null,
  filters jsonb not null default '[]',
  claims jsonb not null,
  created_at timestamp not null default now()
);
create function realtime.topic() returns text language sql stable as $$
  select nullif(current_setting('realtime.topic', true), '')
$$;

-- pgvector stand-ins. Embeddings play no part in who can read a row; these let
-- the tables, functions and queries that mention them be created. (No <->: it
-- would clash with pg_trgm's.)
create domain extensions.vector as text;
create domain extensions.halfvec as text;
create domain extensions.sparsevec as text;
create function extensions.vector_stub_distance(text, text) returns double precision
  language sql immutable as $$ select 0::float8 $$;
create operator extensions.<=> (leftarg = text, rightarg = text, function = extensions.vector_stub_distance);
create operator extensions.<#> (leftarg = text, rightarg = text, function = extensions.vector_stub_distance);

-- Stubs for extensions an in-memory Postgres doesn't have. They let triggers and
-- schedules be created; nothing here sends a request or runs a job.
create function net.http_post(url text, body jsonb default '{}'::jsonb, params jsonb default '{}'::jsonb,
  headers jsonb default '{}'::jsonb, timeout_milliseconds integer default 1000) returns bigint
  language sql as $$ select 0::bigint $$;
create function net.http_get(url text, params jsonb default '{}'::jsonb, headers jsonb default '{}'::jsonb,
  timeout_milliseconds integer default 1000) returns bigint language sql as $$ select 0::bigint $$;
create function cron.schedule(job_name text, schedule text, command text) returns bigint
  language sql as $$ select 0::bigint $$;
create function cron.schedule(schedule text, command text) returns bigint
  language sql as $$ select 0::bigint $$;
create function cron.unschedule(job_name text) returns boolean language sql as $$ select true $$;
create table cron.job (
  jobid bigserial primary key,
  schedule text not null,
  command text not null,
  nodename text not null default 'localhost',
  nodeport integer not null default 5432,
  database text not null default current_database(),
  username text not null default current_user,
  active boolean not null default true,
  jobname text
);
create table cron.job_run_details (
  jobid bigint,
  runid bigserial primary key,
  job_pid integer,
  database text,
  username text,
  command text,
  status text,
  return_message text,
  start_time timestamptz,
  end_time timestamptz
);
create table vault.secrets (id uuid primary key default gen_random_uuid(), name text, secret text);
create view vault.decrypted_secrets as select id, name, secret as decrypted_secret from vault.secrets;
create function vault.create_secret(secret text, name text default null, description text default null)
  returns uuid language sql as $$ insert into vault.secrets (name, secret) values (name, secret) returning id $$;
