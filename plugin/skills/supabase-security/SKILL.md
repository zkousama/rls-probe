---
name: supabase-security
description: Check a Supabase app's database security with rls-probe and fix what it finds. Use after creating or changing anything in supabase/migrations, before deploying, when asked whether a Supabase, Lovable or Bolt app is secure, or when the app gets "permission denied" (42501) after Supabase's October 2026 grants change.
allowed-tools: Bash(npx -y rls-probe@0.5.0 *)
---

# Checking a Supabase app with rls-probe

rls-probe runs the app's migrations in an in-memory Postgres (nothing touches a live
database), signs in two users who each own some rows, and tries every table as a
visitor and as the other user. It also checks the code for leaked keys and open edge
functions.

## Check

Use the `check_supabase_security` tool from this plugin's MCP server. Without it, run:

```sh
npx -y rls-probe@0.5.0 <app folder> --oct30
```

The app folder is the one holding `supabase/migrations` (usually the project root).
Exit code 0 means no problems, 1 means problems were found, 2 means there was nothing
to check (no migrations, or no tables in them).

## Fix

- Get the exact changes with `npx -y rls-probe@0.5.0 <app folder> --prompt`. It names
  the app's own policies and owner columns.
- Put every change in a **new** migration file in `supabase/migrations`. Never edit a
  migration that has already run.
- Keep every user able to see, change and delete their own rows. Never weaken or drop
  a policy just to make the check pass.
- CRITICAL, HIGH and MEDIUM items are problems. Items under "worth a look" may be on
  purpose (public posts, product photos): ask the user before making them private.
- The service role key must never be in front-end code. If rls-probe finds it there,
  move that code into an edge function and tell the user to rotate the key in the
  Supabase dashboard.
- For "permission denied" (42501) after the October 2026 change, only add the grants
  rls-probe marks as safe: the `write_supabase_grants_migration` tool, or `--fix`,
  writes them as a migration. Don't grant anything on tables it holds back until
  their problems are fixed.

## Check again

Run the check again after fixing. Repeat until it reports no problems, or only items
the user confirmed are meant to be public. Then tell the user, in plain words, what
was wrong and what changed.
