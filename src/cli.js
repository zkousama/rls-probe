#!/usr/bin/env node
import path from "node:path";
import { grantsReport, renderGrants } from "./grants.js";
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
const oct30 = args.includes("--oct30");
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
if (json) console.log(JSON.stringify(report, null, 2));
else console.log(renderText({ ...report, load }) + (oct30 ? renderGrants(report.grantsChange) + "\n" : ""));
const g = report.grantsChange;
const grantsTrouble = g && (g.breaks.length || g.unsafe.length || g.closedNoRls.length);
process.exit(findings.some((f) => f.severity !== "review") || grantsTrouble ? 1 : 0);
