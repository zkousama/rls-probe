// Declared access: what each table, bucket and function is meant to allow, written down in
// rls-probe.json, and checked against what the probe saw.
//
//   "access": {
//     "posts":            { "read": "everyone", "add": "signed-in", "change": "owner" },
//     "contact_messages": { "read": "server",   "add": "everyone",  "change": "server" },
//     "bucket:avatars":   { "read": "everyone", "add": "owner",     "change": "owner" },
//     "function:delete_order": { "call": "server" }
//   }
//
// Levels, most open first: everyone (visitors too), signed-in (any signed-in user), team
// (members of the same group), owner (the row's own user) and server (only server code, with
// the service role). "add" means adding rows of one's own; adding them in someone else's name
// is never declared, and stays a problem.
import { findingId } from "./accept.js";

export const LEVELS = ["server", "owner", "team", "signed-in", "everyone"];
const rank = (level) => LEVELS.indexOf(level);
export const VERBS = { read: "see", add: "add", change: "change or delete", call: "call" };
const WORDS = { everyone: "anyone, signed in or not,", "signed-in": "any signed-in user", team: "members of the same team", owner: "only the row's owner", server: "only your server code" };

// "see rows in posts", "add files to the avatars bucket", "call delete_order()".
export function doing(verbs, key) {
  const name = key.replace(/^(bucket|function):/, "");
  if (key.startsWith("function:")) return `call ${name}()`;
  const what = key.startsWith("bucket:") ? "files" : "rows";
  const where = key.startsWith("bucket:") ? `the ${name} bucket` : name;
  if (verbs.length === 1) return `${{ read: `see ${what} in`, add: `add ${what} to`, change: `change or delete ${what} in` }[verbs[0]]} ${where}`;
  // Several verbs: "see, add, change or delete rows in posts".
  const list = ["read", "add", "change"].filter((v) => verbs.includes(v)).flatMap((v) => ({ read: ["see"], add: ["add"], change: ["change", "delete"] })[v]);
  return `${list.slice(0, -1).join(", ")} or ${list.at(-1)} ${what} in ${where}`;
}

// "rls-probe.json says only your server code may see, add, change or delete rows in x":
// verbs that share a level said together.
function saying(declared, verbs, key) {
  const byLevel = {};
  for (const v of verbs) (byLevel[declared[v]] ??= []).push(v);
  return Object.entries(byLevel).map(([level, vs]) => `${WORDS[level]} may ${doing(vs, key)}`).join("; ");
}

// What the probe saw each table, bucket and function allow, as levels.
export function observed(report) {
  const out = {};
  const can = (x, k) => Boolean(x && (k === "read" ? x.read > 0 : x[k]));
  for (const r of report.results.filter((x) => x.anon)) {
    const who = (k) => can(r.anon, k) ? "everyone" : can(r.B, k) ? "signed-in" : r.owned && can(r.D, k) ? "team" : can(r.A, k) ? (r.owned ? "owner" : "signed-in") : "server";
    const change = ["update", "delete"].map(who).sort((a, b) => rank(b) - rank(a))[0];
    out[r.table] = {
      read: who("read"),
      // Adding a row of one's own: a visitor's, or the owner's for themselves.
      add: can(r.anon, "insert") ? "everyone" : can(r.A, "insert") ? "signed-in" : "server",
      change,
      owned: r.owned,
    };
  }
  for (const b of report.storage?.buckets ?? []) {
    if (b.skipped) continue;
    const who = (k) => (b.public && k === "read") || can(b.anon, k) ? "everyone" : can(b.B, k) ? "signed-in" : can(b.A, k) ? "owner" : "server";
    out[`bucket:${b.bucket}`] = { read: who("read"), add: can(b.anon, "insert") ? "everyone" : can(b.A, "insert") ? "signed-in" : "server", change: ["update", "delete"].map(who).sort((a, b) => rank(b) - rank(a))[0], owned: true };
  }
  for (const f of report.findings.filter((x) => x.kind === "definer-function")) out[`function:${f.function}`] = { call: f.callers === "anyone" ? "everyone" : "signed-in" };
  return out;
}

// rls-probe.json's "access", checked: the usable declarations and what's wrong with the rest.
export function readAccess(config) {
  const entries = {};
  const problems = [];
  const unanswered = [];
  for (const [name, verbs] of Object.entries(config?.access ?? {})) {
    for (const [verb, level] of Object.entries(verbs ?? {})) {
      if (!VERBS[verb]) problems.push(`rls-probe.json: "${name}" has "${verb}", which isn't one of ${Object.keys(VERBS).join(", ")}.`);
      else if (typeof level === "string" && level.startsWith("?")) unanswered.push(`${name} (${verb})`);
      else if (!LEVELS.includes(level)) problems.push(`rls-probe.json: "${name}" ${verb} is "${level}"; use one of ${LEVELS.join(", ")}.`);
      else (entries[name] ??= {})[verb] = level;
    }
  }
  if (unanswered.length) problems.push(`rls-probe.json still has ${unanswered.length} question${unanswered.length === 1 ? "" : "s"} to answer (${unanswered.slice(0, 4).join(", ")}${unanswered.length > 4 ? ", ..." : ""}).`);
  return { entries, problems };
}

// Which verb each finding is about.
function verbsOf(f) {
  if (f.kind === "definer-function") return ["call"];
  if (f.kind === "impersonation" || ["service-key", "secret", "browser-secret", "open-function", "view-bypass"].includes(f.kind)) return [];
  if (f.kind === "public-bucket") return ["read"];
  return [...new Set((f.actions ?? ["read"]).map((a) => (a === "read" ? "read" : a === "insert" ? "add" : "change")))];
}

const keyOf = (f) => (f.kind === "definer-function" ? `function:${f.function}` : f.bucket ? `bucket:${f.bucket}` : f.where);

// Applies the declarations to a report's findings: a finding that only does what was declared
// becomes accepted, with the declaration as its reason; one that goes past it says so. Where
// the database allows more than declared and no finding says so, or less (a feature that won't
// work), a finding is added. Returns the new findings, accepted and comparison.
export function applyAccess(report, entries) {
  const seen = observed(report);
  const findings = [];
  const accepted = [];
  for (const f of report.findings) {
    const declared = entries[keyOf(f)];
    const verbs = verbsOf(f);
    if (!declared || !verbs.length || !verbs.every((v) => declared[v])) {
      findings.push(f);
      continue;
    }
    const over = verbs.filter((v) => rank(seen[keyOf(f)]?.[v] ?? declared[v]) > rank(declared[v]));
    if (!over.length) {
      accepted.push({ ...f, reason: `declared in rls-probe.json: ${saying(declared, verbs, keyOf(f))}`, declared: true });
    } else {
      findings.push({ ...f, intent: { verdict: "mistake", reasons: [`rls-probe.json says ${saying(declared, over, keyOf(f))}`, ...(f.intent?.reasons ?? [])] } });
    }
  }
  const covered = new Set(report.findings.map((f) => `${keyOf(f)} ${verbsOf(f).join(",")}`));
  const comparison = [];
  for (const [name, verbs] of Object.entries(entries)) {
    for (const [verb, level] of Object.entries(verbs)) {
      const now = seen[name]?.[verb];
      if (!now) {
        comparison.push({ name, verb, declared: level, observed: null, status: "unknown" });
        continue;
      }
      // A team can only be told apart from owners when the app has teams.
      const status = now === level || (level === "team" && now === "owner" && !report.teams?.length) ? "ok" : rank(now) > rank(level) ? "too open" : "too closed";
      comparison.push({ name, verb, declared: level, observed: now, status });
      const where = name.replace(/^(bucket|function):/, "");
      const already = [...covered].some((c) => c.startsWith(`${name} `) && c.includes(verb));
      if (status === "too open" && !already) {
        findings.push({ kind: "access-too-open", verb, where: name, severity: "high", declared: level, observed: now, title: "Allows more than rls-probe.json says",
          detail: `rls-probe.json says ${WORDS[level]} may ${doing([verb], name)}, but ${WORDS[now]} can.` });
      }
      if (status === "too closed") {
        findings.push({ kind: "access-too-closed", verb, where: name, severity: "review", declared: level, observed: now, title: "Allows less than rls-probe.json says",
          detail: `rls-probe.json says ${WORDS[level]} may ${doing([verb], name)}, but only ${WORDS[now].replace(/^only /, "")} can, so that part of the app may not work.` });
      }
    }
  }
  return { findings, accepted, comparison };
}

// A first rls-probe.json "access" for this app: what the code shows each table is meant to
// allow where it shows it, and a question ("? ...") where only its owner can say. The
// questions list what the database allows now.
export function draftAccess(report) {
  const seen = observed(report);
  const why = {};
  const draft = {};
  for (const [name, now] of Object.entries(seen)) {
    const f = report.findings.find((x) => keyOf(x) === name && x.intent);
    const reasons = f?.intent?.reasons ?? [];
    const entry = {};
    const ask = (verb) => `? ${LEVELS.slice().reverse().join(" | ")} (now: ${now[verb]})`;
    if (name.startsWith("function:")) {
      entry.call = f?.intent?.verdict === "mistake" && /calls it only with the service role|no app code calls it/.test(reasons[0] ?? "") ? "server" : ask("call");
    } else if (f?.intent?.verdict === "mistake" && /only with the service role|plain SQL|no code in this repository|no app code reaches|not for the app's users/.test(reasons[0] ?? "")) {
      // Only server code uses it.
      Object.assign(entry, { read: "server", add: "server", change: "server" });
    } else {
      for (const verb of ["read", "add", "change"]) {
        const about = report.findings.filter((x) => keyOf(x) === name && verbsOf(x).includes(verb));
        // Nothing found for this verb: what the database allows is already as tight as the
        // probe can tell, so it's written down as is.
        if (!about.length) entry[verb] = now[verb];
        else if (about.some((x) => x.intent?.verdict === "on purpose")) entry[verb] = now[verb];
        else if (verb === "read" && about.some((x) => /only reads users' own rows/.test(x.intent?.reasons[0] ?? ""))) entry[verb] = now.owned ? "owner" : "signed-in";
        else entry[verb] = ask(verb);
      }
    }
    draft[name] = entry;
    if (reasons.length) why[name] = reasons[0];
  }
  return { access: draft, why };
}

export function describeLevel(level) {
  return WORDS[level];
}
