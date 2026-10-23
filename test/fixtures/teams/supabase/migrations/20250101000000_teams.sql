-- Organizations with members. Tasks are meant for the organization's members, but the
-- select policy lets any signed-in user read them.
create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null
);
create table public.org_members (
  org_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'member')),
  primary key (org_id, user_id)
);
create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references auth.users (id),
  title text not null,
  client_email text
);

alter table public.organizations enable row level security;
alter table public.org_members enable row level security;
alter table public.tasks enable row level security;

create policy "members see their organization" on public.organizations for select to authenticated
  using (exists (select 1 from public.org_members m where m.org_id = organizations.id and m.user_id = auth.uid()));
create policy "see your memberships" on public.org_members for select to authenticated using (user_id = auth.uid());
create policy "join as yourself" on public.org_members for insert to authenticated with check (user_id = auth.uid());

create policy "signed-in users read tasks" on public.tasks for select to authenticated using (true);
create policy "members edit tasks" on public.tasks for update to authenticated
  using (exists (select 1 from public.org_members m where m.org_id = tasks.org_id and m.user_id = auth.uid()));
create policy "add your own tasks" on public.tasks for insert to authenticated
  with check (user_id = auth.uid() and exists (select 1 from public.org_members m where m.org_id = tasks.org_id and m.user_id = auth.uid()));
