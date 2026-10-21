# rls-probe

Finds what a visitor, or another signed-in user, can read and change in a
Supabase app. It runs the app's migrations in an in-memory Postgres, signs in
two users who each own some rows, and tries every table as a visitor and as the
other user. Nothing touches a live database.

```sh
npx github:zkousama/rls-probe path/to/your-app
```

It reads `supabase/migrations/*.sql` (or `migrations/`, or a folder of `.sql`
files) and, when it's pointed at the app itself, scans the code too.

```
                         visitor (not signed in)     another signed-in user
table       RLS  rows    read  edit  delete  create  read  edit  delete  create
categories  on   shared  yes   -     -       -       yes   -     -       -
messages    on   users   -     -     -       -       yes   yes   -       -
notes       on   users   -     -     -       -       -     -     -       -
orders      OFF  users   yes   yes   yes     yes     yes   yes   yes     yes
profiles    on   users   yes   -     -       -       yes   -     -       -

CRITICAL orders: Row-level security is off
         Anyone with the public key can read, edit, delete and create every row.
         Fix: alter table public.orders enable row level security; then add
         policies that compare the owner column to auth.uid().
```

Exits 1 when it finds something, so it can gate a build.

## Why

Apps built with Lovable, Bolt and other AI builders talk to Supabase straight
from the browser, with a key that ships to every visitor. Row-level security
decides which rows that key can reach. When a table has
it off, or a policy says `using (true)`, anyone can read other people's data, and
often change it. In 2025 a scan of 1,645 Lovable apps found 170 with exactly
that problem (CVE-2025-48757).

Reading policies by eye is slow and easy to get wrong: a policy can look right
and still let one user edit another's rows. So this doesn't read them. It tries.

## What it checks

- **Every table in `public`**, as a visitor with the public key and as a second
  signed-in user: can they read, edit, delete or create rows that belong to
  someone else? A row belongs to a user when a chain of foreign keys leads from
  it to `auth.users`. Tables with no such chain are "shared", like categories,
  and being readable by everyone is often what they're for.
- **Views**, which run with their owner's rights and skip the rules on the
  tables underneath unless they're `security_invoker`.
- **`security definer` functions** that visitors or any user can call, and that
  never check `auth.uid()`.
- **Public storage buckets.**
- **The code**: a service role key or other secret keys in front-end files or a
  build, `VITE_`/`NEXT_PUBLIC_` variables holding secrets, and edge functions with
  `verify_jwt = false` that don't check who's calling.

## Does it match a real Supabase?

`scripts/compare-with-supabase.mjs` starts from a real local Supabase running the
same migrations, signs up two real users, repeats every check over the REST API
and compares. On the test app in `test/fixtures/leaky` all 38 checks agree.

The in-memory database has the parts of Supabase that access rules depend on:
the `anon`, `authenticated` and `service_role` roles, their default grants,
`auth.uid()`, `auth.jwt()`, `auth.users` and the storage tables. Statements that
only matter to a hosted project (realtime publications, comments, extensions
that don't run in memory, like `vector`) are skipped and listed in the report.

## Limits

- It seeds one row per user per table. A policy that depends on data the seed
  doesn't create, such as team membership or an `is_published` flag, may look
  stricter here than it is with real data.
- Tables whose primary key is also the user's id, like `profiles`, can't be
  tested for "create a row for someone else": that row already exists.
- It reads storage bucket settings, not storage policies.
- A finding is a place to look. Some tables are meant to be public; the report
  says so where it can't tell.

## Tests

```sh
npm test
```
