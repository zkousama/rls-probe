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

## Supabase's 2026 grants change

Supabase used to grant `anon` and `authenticated` every table in `public`, and
left row-level security to decide which rows. Projects created since May 30,
2026 no longer get those grants for new tables, and from October 30, 2026 the
same goes for new tables in every project. Tables that already exist keep
their grants. A table without one answers `permission denied` (42501).

The tempting fix for that error is a grant on every table. On a table with
row-level security off, or with a policy that's too loose, that grant is
what exposes the data.

```sh
npx github:zkousama/rls-probe path/to/your-app --oct30
```

adds a section that rebuilds the database without the old grants and sorts
the tables:

```
Safe to grant: row-level security already limits these to the right rows.
  grant select on public.categories to anon, authenticated;
  grant select, insert, update, delete on public.notes to authenticated;

Fix before granting: a grant would open these up.
  messages: Users can change each other's data
  profiles: Visitors can read users' data

Closed only because nothing grants them: row-level security is off, so the quick
fix for 42501, a grant on every table, would expose every row.
  orders: enable row level security and add policies before granting anything.
```

The grants it suggests are the ones each table's policies need, including
`usage` on the sequence behind a `serial` id when users insert rows.
`--grants=explicit` runs the whole probe as a project without the old grants.

## Does it match a real Supabase?

`scripts/compare-with-supabase.mjs` starts from a real local Supabase running the
same migrations, signs up two real users, repeats every check over the REST API
and compares. On the test app in `test/fixtures/leaky` all 38 checks agree.

`scripts/compare-grants-with-supabase.mjs` does the same for the grants change,
on a local Supabase opted in with the SQL from Supabase's changelog: every table
refuses before the suggested grants, and after them each user can create, read
and edit their own rows while a visitor and a second user reach nothing they
shouldn't. 30 of 30 checks pass on `test/fixtures/new-grants`.

`scripts/verify-oct30-on-supabase.mjs` does it for any app: it applies only the
grants marked safe, checks through the API that those tables answer and the
others still refuse, then runs the probe against the real database to show the
grants let nobody reach anything the rules didn't already allow. On a 15-table
open-source app built with Lovable, 57 of 57 checks passed.

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
- By default it gives `anon` and `authenticated` every table in `public`, as Supabase projects have
  done. For a project created since May 30, 2026, use `--grants=explicit`, or the report can show more
  than the API would let through.
- A finding is a place to look. Some tables are meant to be public; the report
  says so where it can't tell.

## Tests

```sh
npm test
```
