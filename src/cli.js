#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { CONFIG } from "./accept.js";
import { draftAccess } from "./access.js";
import { runProbe } from "./engine.js";
import { badge, fixPrompt, renderMarkdown, renderPlain } from "./explain.js";
import { fixesMigration, verifyFixes } from "./fixes.js";
import { migrationFor, renderGrants } from "./grants.js";
import { findMigrations, grantsInBackground, readCodeFiles, readMigrations } from "./node.js";
import { renderText } from "./report.js";
import { reviewBrief } from "./review.js";
import { toSarif } from "./sarif.js";
import { baseSnapshot } from "./snapshot.js";

// `rls-probe mcp` serves the checks to AI agents over stdio, until stdin closes.
if (process.argv[2] === "mcp") {
  (await import("./mcp.js")).serve();
  await new Promise(() => {});
}

const args = process.argv.slice(2);
// What to print: the plain summary and the details (the default), --prompt for an
// AI builder, --review for an AI agent with the code (Claude Code, Cursor, Codex),
// --markdown, --sarif for GitHub code scanning, or --json.
const FORMATS = ["text", "json", "prompt", "review", "markdown", "sarif", "badge"];
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
// --test-fixes tries a fix for each problem on a copy of the database and keeps the
// ones that work; --fix-policies writes those as a new migration. The prompt for AI
// builders includes them.
const fixPolicies = args.includes("--fix-policies");
// --draft-access writes rls-probe.json with an "access" section drafted from the app's code:
// answers where the code shows what a table is for, questions ("? ...") where only you can say.
const draft = args.includes("--draft-access");
const testFixes = args.includes("--test-fixes") || fixPolicies || format === "prompt" || format === "review";
// --fix-time=<seconds>: how long testing fixes may take (three minutes unless set). On a
// very large app, the fixes not tried by then are left out, marked untested.
const fixTime = Number(args.find((a) => a.startsWith("--fix-time="))?.slice(11)) || 180;
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
// The app's rls-probe.json, next to its supabase folder: findings it accepts don't count.
const appRoot = fs.statSync(target).isFile() ? path.dirname(target) : target;
const configFile = path.join(appRoot, CONFIG);
const config = fs.existsSync(configFile) ? fs.readFileSync(configFile, "utf8") : null;
const probed = await runProbe({ migrations, code: readCodeFiles(target), grants, oct30, snapshot, explicitGrants, keep: testFixes, config });
const report = { target, ...probed };
if (testFixes) report.fixes = await verifyFixes({ migrations, report, snapshot, migrated: probed.migrated, trialTime: probed.trialTime, deadline: performance.now() + fixTime * 1000 });
// Supabase keys migrations by their timestamp, so two written in one run are a second apart.
const now = Date.now();
const writeMigration = (name, sql, order) => {
  const stamp = new Date(now + order * 1000).toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const file = path.join(path.dirname(files[0]), `${stamp}_${name}.sql`);
  fs.writeFileSync(file, sql, { flag: "wx" });
  return file;
};
if (fixPolicies) {
  const tested = report.fixes.some((x) => x.verified && report.findings.some((f) => f.severity !== "review" && f.kind === x.kind && f.where === x.where));
  report.policyFixWritten = tested ? writeMigration("rls_probe_security_fixes", fixesMigration(report, VERSION), 0) : null;
}
if (fix) {
  const g = report.grantsChange;
  report.fixWritten = g.breaks.length || g.server.length ? writeMigration("rls_probe_grants", migrationFor(g, VERSION), 1) : null;
}
const shown = path.relative(process.cwd(), target) || ".";
const details = () => renderText({ ...report, target: shown.startsWith("..") ? target : shown }) + (oct30 ? renderGrants(report.grantsChange) + "\n" : "");
const wrote = [
  fixPolicies ? (report.policyFixWritten ? `Wrote ${path.relative(process.cwd(), report.policyFixWritten)}. Read it, then apply it like any migration, and run rls-probe again.` : report.findings.some((f) => f.severity !== "review") ? "No fix passed its test, so no migration was written." : "Nothing to fix, so no migration was written.") : "",
  fix ? (report.fixWritten ? `Wrote ${path.relative(process.cwd(), report.fixWritten)}. Read it, then apply it like any migration.` : "Nothing safe to grant, so no migration was written.") : "",
].filter(Boolean).join("\n");
// SARIF paths are relative to where rls-probe runs: the repository root, in CI.
const posix = (p) => p.split(path.sep).join("/");
const appDir = fs.statSync(target).isFile() ? path.dirname(target) : target;
const sarif = () => JSON.stringify(toSarif(report, {
  base: posix(path.relative(process.cwd(), appDir)),
  migrationsDir: posix(path.relative(appDir, path.dirname(files[0]))) || ".",
  version: VERSION,
}), null, 2);
const markdown = () => renderMarkdown(report, details()) + (wrote ? `\n${wrote}\n` : "");
if (draft) {
  // Answers already in rls-probe.json stay; drafts fill in the rest. The file is written in
  // place, since `--draft-access > rls-probe.json` would empty it before it was read.
  let current = {};
  try {
    current = config ? JSON.parse(config) : {};
  } catch {
    current = {};
  }
  const { access, why } = draftAccess(report);
  // Verb by verb: an answer given wins, the gaps around it are drafted.
  const names = new Set([...Object.keys(access), ...Object.keys(current.access ?? {})]);
  const merged = { ...current, access: Object.fromEntries([...names].sort().map((n) => [n, { ...access[n], ...current.access?.[n] }])) };
  fs.writeFileSync(configFile, `${JSON.stringify(merged, null, 2)}\n`);
  const all = Object.keys(merged.access);
  const count = (n, word) => (n ? `${n} ${word}${n === 1 ? "" : "s"}` : null);
  const what = [count(all.filter((n) => !n.includes(":")).length, "table"), count(all.filter((n) => n.startsWith("bucket:")).length, "bucket"), count(all.filter((n) => n.startsWith("function:")).length, "function")].filter(Boolean);
  const q = Object.values(merged.access).flatMap(Object.values).filter((x) => String(x).startsWith("?")).length;
  console.log(`Wrote ${path.relative(process.cwd(), configFile)}: ${what.length > 1 ? `${what.slice(0, -1).join(", ")} and ${what.at(-1)}` : what[0] ?? "nothing to declare"}, ${q} question${q === 1 ? "" : "s"} for you${q ? ' (marked "?")' : ""}.`);
  console.log(q ? `Answer ${q === 1 ? "it" : "them"}, then run rls-probe again to check the database against your answers.` : "Run rls-probe again to check the database against it.");
  if (Object.keys(why).length) console.log("\nWhat the code shows:");
  for (const [name, reason] of Object.entries(why)) console.log(`  ${name}: ${reason}`);
}
else if (format === "json") console.log(JSON.stringify(report, null, 2));
else if (format === "prompt") process.stdout.write(fixPrompt(report));
else if (format === "review") process.stdout.write(reviewBrief(report));
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
// Exiting at once would cut off a report piped to another program (jq, the MCP
// server) at 64 KB: the exit waits until stdout has taken everything.
// A draft is a file to fill in, not a verdict: it always exits 0.
const code = draft ? 0 : report.findings.some((f) => f.severity !== "review") || grantsTrouble ? 1 : report.results.length ? 0 : 2;
process.stdout.write("", () => process.exit(code));
