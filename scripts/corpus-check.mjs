// Runs rls-probe on every app in a folder and compares the results with an earlier run, so
// a release can't quietly get worse on real apps (the 51 tests passed while fixes stopped
// being verified on some apps).
//
//   node scripts/corpus-check.mjs <apps folder> <results folder> [--against <earlier results>]
//     [--skip=a,b] [--no-fixes] [--timeout=<seconds>]
//
// Each app is a folder (or a link to one) holding its supabase folder. Every app runs one at
// a time with --oct30 --test-fixes --json (--no-fixes: --json only), and its report goes to
// <results folder>/<app>.json. Then it prints the totals, and against an earlier run:
//   worse (exit 1): an app that ran before and doesn't now, a fix verified before that fails
//   now, an app with fewer verified fixes than before;
//   changed (to explain): findings that appeared, went or changed severity, verdicts, and a
//   fix verified before that wasn't tried in time now (on a large app that depends on time).
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const [appsDir, outDir] = args.filter((a) => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--against");
const against = args.includes("--against") ? args[args.indexOf("--against") + 1] : null;
const skip = new Set((args.find((a) => a.startsWith("--skip="))?.slice(7) ?? "").split(",").filter(Boolean));
const fixes = !args.includes("--no-fixes");
const timeout = Number(args.find((a) => a.startsWith("--timeout="))?.slice(10)) || 400;
if (!appsDir || !outDir) {
  console.error("Usage: node scripts/corpus-check.mjs <apps folder> <results folder> [--against <earlier results>] [--skip=a,b] [--no-fixes] [--timeout=<seconds>]");
  process.exit(2);
}
const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
fs.mkdirSync(outDir, { recursive: true });

const apps = fs.readdirSync(appsDir).filter((name) => !name.startsWith(".") && !skip.has(name) && fs.statSync(path.join(appsDir, name)).isDirectory()).sort();
const seconds = {};
for (const app of apps) {
  const started = Date.now();
  const run = spawnSync(process.execPath, [cli, path.join(appsDir, app), ...(fixes ? ["--oct30", "--test-fixes"] : []), "--json"],
    { encoding: "utf8", timeout: timeout * 1000, maxBuffer: 512 * 1024 * 1024 });
  seconds[app] = Math.round((Date.now() - started) / 100) / 10;
  fs.writeFileSync(path.join(outDir, `${app}.json`), run.stdout ?? "");
  fs.writeFileSync(path.join(outDir, `${app}.err`), `${run.stderr ?? ""}${run.error ? `\n${run.error.message}` : ""}`);
  console.log(`${app}: ${run.error ? "timed out" : `exit ${run.status}`}, ${seconds[app]} s`);
}
fs.writeFileSync(path.join(outDir, "seconds.json"), `${JSON.stringify(seconds, null, 2)}\n`);

// One app's results: its findings with severity and verdict, and each fix's outcome.
function read(dir, app) {
  try {
    const r = JSON.parse(fs.readFileSync(path.join(dir, `${app}.json`), "utf8"));
    const id = (f) => `${f.kind}:${f.where ?? f.function ?? f.file ?? ""}`;
    return {
      report: r,
      findings: Object.fromEntries(r.findings.map((f) => [id(f), f.severity])),
      verdicts: Object.fromEntries([...r.findings, ...(r.accepted ?? [])].filter((f) => f.intent).map((f) => [id(f), f.intent.verdict])),
      fixes: Object.fromEntries((r.fixes ?? []).map((f) => [`${f.kind}:${f.where}`, f.verified ? "verified" : f.untested ? "untested" : "failed"])),
    };
  } catch {
    return null;
  }
}

const now = Object.fromEntries(apps.map((app) => [app, read(outDir, app)]));
const ran = Object.values(now).filter(Boolean);
const has = (pred) => ran.filter((a) => a.report.findings.some(pred)).length;
const outcomes = ran.flatMap((a) => Object.values(a.fixes));
const verdicts = ran.flatMap((a) => Object.values(a.verdicts));
const share = (v) => `${Math.round((100 * verdicts.filter((x) => x === v).length) / Math.max(verdicts.length, 1))}%`;
console.log(`\n${ran.length} of ${apps.length} apps ran.`);
console.log(`With a critical or high problem: ${has((f) => f.severity === "critical" || f.severity === "high")}.`);
console.log(`Where a visitor's call to a function changed or deleted another user's data: ${has((f) => f.kind === "definer-function" && f.callers === "anyone" && f.proof?.changed?.some((c) => c.how !== "added"))}.`);
if (fixes) console.log(`Fixes: ${outcomes.length} proposed, ${outcomes.filter((x) => x === "verified").length} verified, ${outcomes.filter((x) => x === "failed").length} failed, ${outcomes.filter((x) => x === "untested").length} not tried in time.`);
if (verdicts.length) console.log(`Verdicts: ${verdicts.length}; likely a mistake ${share("mistake")}, likely on purpose ${share("on purpose")}, can't tell ${share("unclear")}.`);

if (!against) process.exit(0);
const worse = [];
const changed = [];
for (const app of apps) {
  const was = read(against, app);
  const is = now[app];
  if (!was) continue;
  if (!is) {
    worse.push(`${app}: ran before, not now`);
    continue;
  }
  for (const [fix, outcome] of Object.entries(was.fixes)) {
    if (outcome === "verified" && is.fixes[fix] === "failed") worse.push(`${app}: ${fix} was verified, now fails`);
    if (outcome === "verified" && is.fixes[fix] === "untested") changed.push(`${app}: ${fix} was verified, now not tried in time`);
  }
  const verified = (r) => Object.values(r.fixes).filter((x) => x === "verified").length;
  if (verified(is) < verified(was)) worse.push(`${app}: ${verified(was)} fixes verified before, ${verified(is)} now`);
  for (const id of new Set([...Object.keys(was.findings), ...Object.keys(is.findings)])) {
    if (!(id in was.findings)) changed.push(`${app}: new ${is.findings[id]} ${id}`);
    else if (!(id in is.findings)) changed.push(`${app}: gone ${was.findings[id]} ${id}`);
    else if (was.findings[id] !== is.findings[id]) changed.push(`${app}: ${id} ${was.findings[id]} -> ${is.findings[id]}`);
    else if (was.verdicts[id] && is.verdicts[id] && was.verdicts[id] !== is.verdicts[id]) changed.push(`${app}: ${id} verdict ${was.verdicts[id]} -> ${is.verdicts[id]}`);
  }
}
console.log(`\nAgainst ${against}: ${worse.length} worse, ${changed.length} changed.`);
for (const line of worse) console.log(`  WORSE   ${line}`);
for (const line of changed) console.log(`  changed ${line}`);
process.exit(worse.length ? 1 : 0);
