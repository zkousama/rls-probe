---
name: supabase-security
description: Check a Supabase app's database security with rls-probe and fix what it finds. Use after creating or changing anything in supabase/migrations, before deploying, when asked whether a Supabase, Lovable or Bolt app is secure, or when the app gets "permission denied" (42501) after Supabase's October 2026 grants change.
allowed-tools: Bash(npx -y rls-probe@0.10.3 *)
---

# Checking a Supabase app with rls-probe

rls-probe runs the app's migrations in an in-memory Postgres (nothing touches a live
database), signs in two users who each own some rows, and tries every table as a
visitor and as the other user. It also checks the code for leaked keys and open edge
functions.

## Check

Use the `check_supabase_security` tool from this plugin's MCP server. Without it, run:

```sh
npx -y rls-probe@0.10.3 <app folder> --oct30
```

The app folder is the one holding `supabase/migrations` (usually the project root).
Exit code 0 means no problems, 1 means problems were found, 2 means there was nothing
to check (no migrations, or no tables in them).

## Fix

- rls-probe only sees the database the migrations build. Check each finding against the
  code before changing anything: `npx -y rls-probe@0.10.3 <app folder> --review` gives,
  for each one, what rls-probe saw, the migration lines behind it, a check to run on a
  local database, and why it might not apply. Decide whether it's real, already handled,
  on purpose or wrong.
- Record the ones you rule out in `rls-probe.json` at the app's root, with the reason
  (`{ "accept": [{ "finding": "visitor-read:products", "reason": "a public catalog" }] }`),
  so they're listed as accepted instead of counted. Ask the user before accepting anything
  that holds private data.
- To record who each table is for, run `npx -y rls-probe@0.10.3 <app folder> --draft-access`.
  It writes an `access` section into `rls-probe.json` (who may see, add and change each
  table: everyone, signed-in, team, owner or server), drafted from the code, and keeps
  what's already there. Ask the user every question it marks with "?"; never answer
  those yourself. From then on, findings that match the answers stop counting.
- Get the exact changes with `npx -y rls-probe@0.10.3 <app folder> --prompt`. It names
  the app's own policies and owner columns, and gives SQL that rls-probe already
  tested on a copy of the database: prefer it. The `write_supabase_security_fixes`
  tool, or `--fix-policies`, writes all the tested fixes as one migration.
- Each tested fix says what changes afterwards ("each signed-in user sees only their
  own rows in posts"). When that would limit a feature the app has, such as a public
  feed, tell the user and ask before applying it.
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
