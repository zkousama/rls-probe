// The whole probe as one call, with no file or Node access: the CLI, the MCP
// server and the web page all hand it the app's files and get the report back.
import { grantsReport } from "./grants.js";
import { loadDatabase } from "./load.js";
import { probeTables, probeViews } from "./probe.js";
import { ORDER, findingsFrom } from "./report.js";
import { readBuckets, readFunctions, readPolicies, readSchema } from "./schema.js";
import { ownerRoute, seed } from "./seed.js";
import { scanCode } from "./static.js";

// migrations: [{ name, sql }] in the order they run. code: [{ path, text }] for the
// code scan. snapshot: the base database (see snapshot.js, or the web page's copy).
// explicitGrants: for --oct30 with the old grants, a function the caller started
// early (a worker in Node) that takes the findings and returns the grants report;
// without one, the second database is built here, after the first is closed.
// onProgress: told each step as it starts ("migrations", "seed", "probe", "grants").
export async function runProbe({ migrations, code = [], grants = "legacy", oct30 = false, snapshot, explicitGrants, onProgress = () => {} }) {
  onProgress("migrations");
  const load = await loadDatabase(migrations, { grants, snapshot });
  const tables = await readSchema(load.db);
  onProgress("seed");
  const { known, problems } = await seed(load.db, tables);
  onProgress("probe");
  const results = await probeTables(load.db, tables, known);
  const views = await probeViews(load.db, tables);
  const functions = await readFunctions(load.db);
  const buckets = await readBuckets(load.db);
  const policies = await readPolicies(load.db);
  const findings = [...findingsFrom(results, views, functions, buckets), ...scanCode(code)];
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);

  // How each owned table's rows lead to a user, for fixes that name the column.
  for (const r of results) {
    const table = tables.find((t) => t.name === r.table);
    if (r.owned && table) r.ownedThrough = ownerRoute(table, tables);
  }
  const report = {
    grants,
    migrations: migrations.length,
    load: { applied: load.applied, skipped: load.skipped, failed: load.failed, missing: load.missing },
    seedProblems: problems,
    results,
    views,
    findings,
    policies: byTable(policies),
    createdAt: locate(migrations),
  };
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
