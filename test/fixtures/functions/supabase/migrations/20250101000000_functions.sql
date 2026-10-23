-- Security definer functions, each called by rls-probe as a visitor and as another user.
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  display_name text
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for all to authenticated using (id = auth.uid()) with check (id = auth.uid());

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id),
  name text not null,
  view_count int not null default 0
);
alter table public.projects enable row level security;
create policy "own projects" on public.projects for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());

-- Checks that someone is signed in, never that the project is theirs.
create function public.rename_project(project_id uuid, new_name text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'sign in first'; end if;
  update projects set name = new_name where id = project_id;
end $$;
revoke execute on function public.rename_project(uuid, text) from public, anon;
grant execute on function public.rename_project(uuid, text) to authenticated;

-- Hands anyone a user's profile, email included.
create function public.get_profile(uid uuid) returns setof public.profiles
language sql security definer set search_path = public as $$
  select * from profiles where id = uid;
$$;

-- Counts a view: meant for anyone.
create function public.bump_views(project_id uuid) returns void
language sql security definer set search_path = public as $$
  update projects set view_count = view_count + 1 where id = project_id;
$$;

-- Deletes only the caller's own project.
create function public.delete_my_project(project_id uuid) returns void
language sql security definer set search_path = public as $$
  delete from projects where id = project_id and owner_id = auth.uid();
$$;
