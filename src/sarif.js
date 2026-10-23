// SARIF 2.1.0, the format GitHub code scanning reads, so findings show in a
// repository's Security tab and on the lines of a pull request.
import { explain } from "./explain.js";

const LEVEL = { critical: "error", high: "error", medium: "warning", review: "note" };
// GitHub sorts and labels code scanning alerts by this number (0 to 10).
const SCORE = { critical: "9.5", high: "8.0", medium: "5.5", review: "3.0" };

// base: the app's folder, relative to the root SARIF paths are read from (the
// repository root in CI). migrationsDir: the migrations' folder, relative to the app.
export function toSarif(report, { base = "", migrationsDir = "supabase/migrations", version = "" } = {}) {
  const at = (p) => [base, p].filter((x) => x && x !== ".").join("/") || ".";
  const e = explain(report);
  const said = [...e.problems, ...e.notes];
  const rules = new Map();
  // Findings accepted in rls-probe.json go in as suppressed, with the reason, so code
  // scanning shows them closed rather than missing.
  const results = [...report.findings, ...(report.accepted ?? [])].map((f) => {
    const id = `${f.kind ?? "finding"}/${f.severity}`;
    if (!rules.has(id)) {
      rules.set(id, {
        id,
        name: f.kind ?? "finding",
        shortDescription: { text: f.title },
        helpUri: "https://github.com/zkousama/rls-probe#what-it-checks",
        properties: { tags: ["security", "supabase", "rls"], "security-severity": SCORE[f.severity] },
      });
    }
    const plain = said.find((s) => s.where === f.where && s.severity === f.severity);
    return {
      ruleId: id,
      level: LEVEL[f.severity],
      message: { text: plain ? `${plain.headline} ${plain.ask}` : `${f.title}: ${f.detail}` },
      locations: [{ physicalLocation: location(f, report, at(migrationsDir), at) }],
      ...(f.reason ? { suppressions: [{ kind: "external", justification: f.reason }] } : {}),
    };
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "rls-probe", version, informationUri: "https://github.com/zkousama/rls-probe", rules: [...rules.values()] } }, results }],
  };
}

function location(f, report, migrationsDir, at) {
  const code = /^(.+):(\d+)$/.exec(f.where);
  if (code && !f.where.includes("(")) return { artifactLocation: { uri: at(code[1]) }, region: { startLine: Number(code[2]) } };
  if (f.kind === "open-function") return { artifactLocation: { uri: at("supabase/config.toml") }, region: { startLine: 1 } };
  const name = f.kind === "definer-function" ? f.function : f.kind === "public-bucket" ? null : f.where;
  const created = name && report.createdAt?.[name];
  const first = Object.values(report.createdAt ?? {})[0];
  const file = created?.file ?? first?.file;
  return file
    ? { artifactLocation: { uri: `${migrationsDir}/${file}` }, region: { startLine: created?.line ?? 1 } }
    : { artifactLocation: { uri: migrationsDir }, region: { startLine: 1 } };
}
