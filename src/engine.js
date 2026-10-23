// The whole probe as one call, with no file or Node access: the CLI, the MCP
// server and the web page all hand it the app's files and get the report back.
import { applyAccept, readAccept } from "./accept.js";
import { grantsReport } from "./grants.js";
import { loadDatabase } from "./load.js";
import { probeFunctions, probeStorage, probeTables, probeViews } from "./probe.js";
import { ORDER, findingsFrom } from "./report.js";
import { readBuckets, readFunctions, readGuards, readPolicies, readSchema } from "./schema.js";
import { groupRoutes, ownerRoute, partyRoutes, seed } from "./seed.js";
import { configBuckets, scanCode } from "./static.js";

// migrations: [{ name, sql }] in the order they run. code: [{ path, text }] for the
// code scan. snapshot: the base database (see snapshot.js, or the web page's copy).
// explicitGrants: for --oct30 with the old grants, a function the caller started
// early (a worker in Node) that takes the findings and returns the grants report;
// without one, the second database is built here, after the first is closed.
// onProgress: told each step as it starts ("migrations", "seed", "probe", "grants").
// keep: save a copy of the database once the migrations have run, as the report's
// `migrated` (not part of its JSON), so fixes can be tried on it without running the
// migrations again. from: such a copy, to run `migrations` on instead. call: whether
// to call the security definer functions (trying fixes doesn't need to). config: the
// text of the app's rls-probe.json, whose accepted findings don't count (see accept.js).
export async function runProbe({ migrations, code = [], grants = "legacy", oct30 = false, snapshot, explicitGrants, onProgress = () => {}, keep = false, from, call = true, config }) {
  onProgress("migrations");
  const load = await loadDatabase(migrations, { grants, snapshot, from });
  const migrated = keep ? { dataDir: await load.db.dumpDataDir("none"), extensions: load.extensions } : null;
  const tables = await readSchema(load.db);
  onProgress("seed");
  const seeded = performance.now();
  const { known, problems, teams } = await seed(load.db, tables);
  onProgress("probe");
  const results = await probeTables(load.db, tables, known, { teammate: teams.length > 0 });
  const views = await probeViews(load.db, tables);
  // Storage is probed on its own terms: if a project's storage schema is too unusual
  // to probe, the tables' results still stand.
  // Buckets declared in supabase/config.toml, which Supabase creates from it, not from migrations.
  const declared = configBuckets(code.find((f) => f.path === "supabase/config.toml")?.text);
  const storage = await probeStorage(load.db, declared).catch((error) => ({ rls: null, buckets: [], policies: [], error: error.message }));
  const functions = await readFunctions(load.db);
  const guards = await readGuards(load.db).catch(() => new Set());
  // Calling functions is the newest probe: if it fails, the rest of the report stands.
  const calls = call ? await probeFunctions(load.db, functions, tables, known).catch(() => []) : [];
  for (const f of functions) Object.assign(f, calls.find((c) => c.name === f.name && c.args === f.args) ?? {}, { name: f.name, args: f.args });
  const buckets = await readBuckets(load.db);
  const policies = await readPolicies(load.db);
  const accept = readAccept(config);
  const { findings, accepted, unused } = applyAccept([...findingsFrom(results, views, functions, buckets, storage, guards), ...scanCode(code)], accept.entries);
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);

  // How each owned table's rows lead to a user, for fixes that name the column.
  for (const r of results) {
    const table = tables.find((t) => t.name === r.table);
    if (r.owned && table) {
      r.ownedThrough = ownerRoute(table, tables);
      r.parties = partyRoutes(table, tables);
      if (teams.length) r.groups = groupRoutes(table, tables, teams);
    }
  }
  const report = {
    grants,
    migrations: migrations.length,
    load: { applied: load.applied, skipped: load.skipped, failed: load.failed, missing: load.missing },
    seedProblems: problems,
    // Membership tables through which a teammate (D) joined user A's group.
    teams,
    results,
    views,
    functions: calls,
    storage: { rls: storage.rls, buckets: storage.buckets, ...(storage.error ? { error: storage.error } : {}) },
    findings,
    // Findings the app's rls-probe.json accepts, with its reasons, and what's off in that file.
    accepted,
    acceptNotes: [...accept.problems, ...(unused.length ? [`rls-probe.json accepts ${unused.join(", ")}, which no longer ${unused.length === 1 ? "comes" : "come"} up. Remove ${unused.length === 1 ? "it" : "them"}.`] : [])],
    policies: { ...byTable(policies), ...(storage.policies.length ? { "storage.objects": storage.policies.map((p) => ({ name: p.name, cmd: p.cmd, roles: p.roles, using: p.qual, check: p.check })) } : {}) },
    createdAt: locate(migrations),
    policyAt: locatePolicies(migrations),
  };
  if (migrated) Object.defineProperty(report, "migrated", { value: migrated, enumerable: false });
  // Roughly what trying a set of fixes costs: everything after the migrations.
  Object.defineProperty(report, "trialTime", { value: performance.now() - seeded, enumerable: false });
  if (oct30) onProgress("grants");
  if (oct30 && grants === "explicit") report.grantsChange = await grantsReport(load.db, findings);
  await load.db.close().catch(() => {});
  if (oct30 && grants === "legacy") {
    if (explicitGrants) report.grantsChange = await explicitGrants(findings);
    else {
      const second = await loadDatabase(migrations, { grants: "explicit", snapshot });
      report.grantsChange = await grantsReport(second.db, findings);
      await second.db.close().catch(() => {});
    }
  }
  return report;
}

// The first file and line that creates each policy, by table and name.
function locatePolicies(migrations) {
  const out = {};
  const create = /\bcreate\s+policy\s+(?:"([^"]+)"|(\w+))\s+on\s+(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?/gi;
  for (const m of migrations) {
    m.sql.split("\n").forEach((line, i) => {
      for (const hit of line.matchAll(create)) {
        const table = hit[3] === "storage" ? `storage.${hit[4]}` : hit[4];
        (out[table] ??= {})[hit[1] ?? hit[2]] ??= { file: m.name, line: i + 1 };
      }
    });
  }
  return out;
}

function byTable(policies) {
  const out = {};
  for (const p of policies) (out[p.table] ??= []).push({ name: p.name, cmd: p.cmd, roles: p.roles, using: p.qual, check: p.check });
  return out;
}

// The first file and line that creates each table, view or function, so a report
// can point at it.
function locate(migrations) {
  const out = {};
  const create = /\bcreate\s+(?:or\s+replace\s+)?(?:unlogged\s+)?(?:table|view|materialized\s+view|function)\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\s*\.\s*)?"?(\w+)"?/gi;
  for (const m of migrations) {
    m.sql.split("\n").forEach((line, i) => {
      for (const hit of line.matchAll(create)) out[hit[1]] ??= { file: m.name, line: i + 1 };
    });
  }
  return out;
}
