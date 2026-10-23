-- What each table is for shows in the app's code and in these comments; rls-probe reads both.
create table public.waitlist (id bigint generated always as identity primary key, email text not null);

create table public.legacy_stats (id bigint generated always as identity primary key, day date not null, signups int not null);

create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), body text);
alter table public.notes enable row level security;
create policy "read notes" on public.notes for select to authenticated using (true);
create policy "own notes" on public.notes for insert to authenticated with check (user_id = auth.uid());

create table public.posts (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), title text);
alter table public.posts enable row level security;
create policy "read posts" on public.posts for select to authenticated using (true);

create table public.contact_messages (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users (id), message text not null);
alter table public.contact_messages enable row level security;
-- Anyone can send us a message from the contact page.
create policy "Anyone can submit" on public.contact_messages for insert to anon, authenticated with check (true);
