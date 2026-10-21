#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { grantsReport, migrationFor, renderGrants } from "./grants.js";
import { findMigrations, loadDatabase } from "./load.js";
import { probeTables, probeViews } from "./probe.js";
import { findingsFrom, renderText } from "./report.js";
import { readBuckets, readFunctions, readSchema } from "./schema.js";
import { seed } from "./seed.js";
import { scanFiles } from "./static.js";

const args = process.argv.slice(2);
const json = args.includes("--json");
// --grants=explicit runs the whole probe as a project without Supabase's old default
// grants; --oct30 adds a section on what the grants change breaks and what's safe to grant.
const grants = args.includes("--grants=explicit") ? "explicit" : "legacy";
// --fix writes the safe grants as a new migration next to the others (it implies --oct30).
const fix = args.includes("--fix");
const oct30 = args.includes("--oct30") || fix;
const VERSION = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const target = path.resolve(args.find((a) => !a.startsWith("--")) ?? ".");

const files = findMigrations(target);
if (!files.length) {
  console.error(`No .sql migrations found in ${target}, ${path.join(target, "supabase", "migrations")} or ${path.join(target, "migrations")}.`);
  process.exit(2);
}

const load = await loadDatabase(files, { grants });
const tables = await readSchema(load.db);
const { known, problems } = await seed(load.db, tables);
const results = await probeTables(load.db, tables, known);
const views = await probeViews(load.db, tables);
const functions = await readFunctions(load.db);
const buckets = await readBuckets(load.db);
const findings = [...findingsFrom(results, views, functions, buckets), ...scanFiles(target)];
findings.sort((a, b) => ({ critical: 0, high: 1, medium: 2, review: 3 })[a.severity] - ({ critical: 0, high: 1, medium: 2, review: 3 })[b.severity]);

const report = { target, grants, migrations: files.length, load: { applied: load.applied, skipped: load.skipped, failed: load.failed }, seedProblems: problems, results, views, findings };
if (oct30) report.grantsChange = await grantsReport((await loadDatabase(files, { grants: "explicit" })).db, findings);
if (fix) {
  const g = report.grantsChange;
  if (!g.breaks.length) report.fixWritten = null;
  else {
    const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
    const file = path.join(path.dirname(files[0]), `${stamp}_rls_probe_grants.sql`);
    fs.writeFileSync(file, migrationFor(g, VERSION), { flag: "wx" });
    report.fixWritten = file;
  }
}
if (json) console.log(JSON.stringify(report, null, 2));
else {
  const shown = path.relative(process.cwd(), target) || ".";
  console.log(renderText({ ...report, target: shown.startsWith("..") ? target : shown, load }) + (oct30 ? renderGrants(report.grantsChange) + "\n" : ""));
  if (fix) console.log(report.fixWritten ? `Wrote ${path.relative(process.cwd(), report.fixWritten)}. Read it, then apply it like any migration.` : "Nothing safe to grant, so no migration was written.");
}
const g = report.grantsChange;
// After --fix, the grants it wrote no longer count against the exit code.
const grantsTrouble = g && ((fix ? 0 : g.breaks.length) || g.unsafe.length || g.closedNoRls.length);
process.exit(findings.some((f) => f.severity !== "review") || grantsTrouble ? 1 : 0);
