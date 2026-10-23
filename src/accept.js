// rls-probe.json: an app's own record of findings someone checked and accepted, each with
// the reason, so rls-probe stops counting them:
//   { "accept": [{ "finding": "visitor-read:products", "reason": "a public catalog" }] }
// Accepted findings are still listed, with their reasons; an entry without a reason is
// ignored, and one that no longer matches anything is pointed out.
export const CONFIG = "rls-probe.json";

// A finding's name in reports and in rls-probe.json.
export const findingId = (f) => `${f.kind}:${f.where}`;

// text: the file's contents, or nothing. Returns the usable entries and what's wrong
// with the rest.
export function readAccept(text) {
  if (!text) return { entries: [], problems: [] };
  let config;
  try {
    config = JSON.parse(text);
  } catch (error) {
    return { entries: [], problems: [`${CONFIG} isn't valid JSON (${error.message}), so nothing in it was applied.`] };
  }
  const entries = [];
  const problems = [];
  for (const entry of Array.isArray(config?.accept) ? config.accept : []) {
    if (typeof entry?.finding !== "string" || !entry.finding.includes(":")) problems.push(`${CONFIG}: ${JSON.stringify(entry)} names no finding (they look like "visitor-read:products").`);
    else if (typeof entry.reason !== "string" || !entry.reason.trim()) problems.push(`${CONFIG}: ${entry.finding} has no reason, so it still counts. Say why it's fine.`);
    else entries.push({ finding: entry.finding, reason: entry.reason.trim() });
  }
  return { entries, problems };
}

// Splits the findings into those that count and those accepted, and names the entries
// that matched nothing (fixed since, or renamed).
export function applyAccept(findings, entries) {
  const byId = new Map(entries.map((e) => [e.finding, e.reason]));
  const accepted = findings.filter((f) => byId.has(findingId(f))).map((f) => ({ ...f, reason: byId.get(findingId(f)) }));
  const ids = new Set(findings.map(findingId));
  return {
    findings: findings.filter((f) => !byId.has(findingId(f))),
    accepted,
    unused: entries.filter((e) => !ids.has(e.finding)).map((e) => e.finding),
  };
}
