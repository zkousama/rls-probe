create extension if not exists "uuid-ossp" with schema extensions;
create extension if not exists vector with schema extensions;

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text,
  email text not null,
  created_at timestamptz default now()
);
alter table public.profiles enable row level security;
-- "Profiles are viewable by everyone": a common generated policy
create policy "Profiles are viewable by everyone" on public.profiles for select using (true);
create policy "Users can update own profile" on public.profiles for update using (auth.uid() = id);

create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name) values (new.id, new.email, new.raw_user_meta_data ->> 'full_name');
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

-- orders: no row-level security at all
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  total numeric not null,
  status text not null default 'pending',
  embedding vector(3)
);

-- messages: RLS on, but any signed-in user can read and edit every row
create table public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null references public.profiles (id),
  body text not null
);
alter table public.messages enable row level security;
create policy "auth read" on public.messages for select to authenticated using (true);
create policy "auth write" on public.messages for update to authenticated using (true);
create policy "own insert" on public.messages for insert to authenticated with check (sender_id = auth.uid());

-- notes: done right
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id),
  body text
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());

-- categories: public catalog, no owner
create table public.categories (id serial primary key, name text not null unique);
alter table public.categories enable row level security;
create policy "public read" on public.categories for select using (true);

alter publication supabase_realtime add table public.messages;
comment on table public.orders is 'orders';

create function public.delete_order(order_id uuid) returns void language sql security definer as $$
  delete from public.orders where id = order_id
$$;
create view public.order_totals as select user_id, sum(total) as total from public.orders group by user_id;
insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);
