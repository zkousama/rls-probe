#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { runProbe } from "./engine.js";
import { badge, fixPrompt, renderMarkdown, renderPlain } from "./explain.js";
import { migrationFor, renderGrants } from "./grants.js";
import { findMigrations, grantsInBackground, readCodeFiles, readMigrations } from "./node.js";
import { renderText } from "./report.js";
import { toSarif } from "./sarif.js";
import { baseSnapshot } from "./snapshot.js";

// `rls-probe mcp` serves the checks to AI agents over stdio, until stdin closes.
if (process.argv[2] === "mcp") {
  (await import("./mcp.js")).serve();
  await new Promise(() => {});
}

const args = process.argv.slice(2);
// What to print: the plain summary and the details (the default), --prompt for an
// AI builder, --markdown, --sarif for GitHub code scanning, or --json.
const FORMATS = ["text", "json", "prompt", "markdown", "sarif", "badge"];
const format = args.find((a) => a.startsWith("--format="))?.slice(9) ?? FORMATS.find((f) => args.includes(`--${f}`)) ?? "text";
if (!FORMATS.includes(format)) {
  console.error(`Unknown format "${format}". Use one of: ${FORMATS.join(", ")}.`);
  process.exit(2);
}
// --grants=explicit runs the whole probe as a project without Supabase's old default
// grants; --oct30 adds a section on what the grants change breaks and what's safe to grant.
const grants = args.includes("--grants=explicit") ? "explicit" : "legacy";
// --fix writes the safe grants as a new migration next to the others (it implies --oct30).
const fix = args.includes("--fix");
const oct30 = args.includes("--oct30") || fix;
const VERSION = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const target = path.resolve(args.find((a) => !a.startsWith("--")) ?? ".");
// Extra copies in other formats, written in the same run (the GitHub Action uses both).
const markdownFile = args.find((a) => a.startsWith("--markdown-file="))?.slice(16);
const sarifFile = args.find((a) => a.startsWith("--sarif-file="))?.slice(13);

const files = findMigrations(target);
if (!files.length) {
  console.error(`No .sql migrations found in ${target}, ${path.join(target, "supabase", "migrations")} or ${path.join(target, "migrations")}.`);
  process.exit(2);
}

const migrations = readMigrations(files);
const snapshot = await baseSnapshot();
// --oct30 compares against a database without the old grants. When the probe runs
// with them, that second database loads in a worker meanwhile.
const explicitGrants = oct30 && grants === "legacy" ? grantsInBackground(migrations, snapshot) : null;
const report = { target, ...(await runProbe({ migrations, code: readCodeFiles(target), grants, oct30, snapshot, explicitGrants })) };
if (fix) {
  const g = report.grantsChange;
  if (!g.breaks.length && !g.server.length) report.fixWritten = null;
  else {
    const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
    const file = path.join(path.dirname(files[0]), `${stamp}_rls_probe_grants.sql`);
    fs.writeFileSync(file, migrationFor(g, VERSION), { flag: "wx" });
    report.fixWritten = file;
  }
}
const shown = path.relative(process.cwd(), target) || ".";
const details = () => renderText({ ...report, target: shown.startsWith("..") ? target : shown }) + (oct30 ? renderGrants(report.grantsChange) + "\n" : "");
const wrote = fix ? (report.fixWritten ? `Wrote ${path.relative(process.cwd(), report.fixWritten)}. Read it, then apply it like any migration.` : "Nothing safe to grant, so no migration was written.") : "";
// SARIF paths are relative to where rls-probe runs: the repository root, in CI.
const posix = (p) => p.split(path.sep).join("/");
const appDir = fs.statSync(target).isFile() ? path.dirname(target) : target;
const sarif = () => JSON.stringify(toSarif(report, {
  base: posix(path.relative(process.cwd(), appDir)),
  migrationsDir: posix(path.relative(appDir, path.dirname(files[0]))) || ".",
  version: VERSION,
}), null, 2);
const markdown = () => renderMarkdown(report, details()) + (wrote ? `\n${wrote}\n` : "");
if (format === "json") console.log(JSON.stringify(report, null, 2));
else if (format === "prompt") process.stdout.write(fixPrompt(report));
else if (format === "markdown") console.log(markdown());
else if (format === "sarif") console.log(sarif());
else if (format === "badge") {
  const line = badge(report);
  console.log(line ? `${line}\n\nThis shows today's grade. Run rls-probe again after changes (or in CI) to keep it honest.` : "Nothing was checked, so there's no grade to show.");
}
else console.log(`${renderPlain(report)}\nDetails\n\n${details()}${wrote ? `\n${wrote}` : ""}`);
if (markdownFile) fs.writeFileSync(markdownFile, markdown());
if (sarifFile) fs.writeFileSync(sarifFile, sarif());
const g = report.grantsChange;
// After --fix, the grants it wrote no longer count against the exit code.
const grantsTrouble = g && ((fix ? 0 : g.breaks.length + g.server.length) || g.unsafe.length || g.closedNoRls.length);
// 1: something to fix. 2: no tables, so nothing was checked (not an all clear).
process.exit(report.findings.some((f) => f.severity !== "review") || grantsTrouble ? 1 : report.results.length ? 0 : 2);
