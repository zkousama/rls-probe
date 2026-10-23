// "What each table is for": the access rls-probe drafted from the app's code (rls-probe.json's
// "access"), one-click answers for what the code couldn't tell, a check of the database against
// them without probing again, and the file to keep in the repository.
import { LEVELS, applyAccess, doing, draftAccess, observed } from "../../../src/access.js";

const LABEL = { everyone: "Anyone", "signed-in": "Signed-in users", team: "Their team", owner: "Only the owner", server: "Only your server" };
// Who may add rows: one's own rows, so team and owner mean any signed-in user. Functions: who may call.
const CHOICES = { read: LEVELS, change: LEVELS, add: ["server", "signed-in", "everyone"], call: ["server", "signed-in", "everyone"] };

// report: the inspection; project.config: the app's rls-probe.json, if any. check(entries, file):
// re-grades the inspection against the answers. Returns the section's body.
export function declareParts(report, project, el, { check, download }) {
  const base = report.undeclared ?? { findings: report.findings, accepted: report.accepted };
  const { access, why } = draftAccess({ ...report, findings: base.findings });
  const now = observed(report);
  const file = parse(project.config);
  const answered = Object.keys(file.access ?? {}).length > 0;
  // Answers already in rls-probe.json win over the draft.
  const answers = {};
  for (const [name, verbs] of Object.entries(access)) {
    answers[name] = {};
    for (const [verb, level] of Object.entries(verbs)) {
      const given = file.access?.[name]?.[verb];
      answers[name][verb] = LEVELS.includes(given) ? given : String(level).startsWith("?") ? null : level;
    }
  }
  const asked = Object.entries(answers).flatMap(([name, verbs]) => Object.entries(verbs).filter(([, l]) => l === null).map(([verb]) => [name, verb]));

  const choose = (name, verb, row) => {
    const options = CHOICES[verb].slice().reverse();
    const buttons = options.map((level) => {
      const b = el("button", { type: "button", className: "level" }, LABEL[level], ...(now[name]?.[verb] === level ? [el("span", { className: "level-now" }, " now")] : []));
      b.setAttribute("aria-pressed", String(answers[name][verb] === level));
      b.addEventListener("click", () => {
        answers[name][verb] = level;
        for (const x of buttons) x.setAttribute("aria-pressed", String(x === b));
        row?.classList.add("answered");
      });
      return b;
    });
    return el("div", { className: "levels", role: "group", ariaLabel: `Who should be able to ${doing([verb], name)}` }, ...buttons);
  };

  const questions = asked.map(([name, verb]) => {
    const row = el("div", { className: "question" });
    row.append(el("p", { className: "font-semibold" }, `Who should be able to ${doing([verb], name)}?`),
      ...(why[name] ? [el("p", { className: "text-[0.9rem] text-muted" }, `What the code shows: ${end(why[name])}`)] : []),
      choose(name, verb, row));
    return row;
  });

  const filled = Object.entries(answers).filter(([name, verbs]) => Object.values(verbs).some((l) => l !== null)).map(([name, verbs]) => el("div", { className: "question" },
    el("p", { className: "font-semibold font-mono text-[0.9rem]" }, name.replace(/^function:/, "function ").replace(/^bucket:/, "bucket ")),
    ...(why[name] ? [el("p", { className: "text-[0.9rem] text-muted" }, end(`${why[name].charAt(0).toUpperCase()}${why[name].slice(1)}`))] : []),
    ...Object.entries(verbs).filter(([, l]) => l !== null).map(([verb]) => el("div", { className: "mt-2" },
      el("p", { className: "text-[0.9rem]" }, `Who may ${doing([verb], name)}`), choose(name, verb, null))),
  ));

  const entries = () => Object.fromEntries(Object.entries(answers).map(([n, v]) => [n, Object.fromEntries(Object.entries(v).filter(([, l]) => l))]).filter(([, v]) => Object.keys(v).length));
  // The file: what's there already, with the answers; questions left open stay as "? ..." for later.
  const json = () => {
    const out = { ...file, access: {} };
    for (const [name, verbs] of Object.entries(answers)) {
      out.access[name] = Object.fromEntries(Object.entries(verbs).map(([verb, l]) => [verb, l ?? `? ${CHOICES[verb].slice().reverse().join(" | ")} (now: ${now[name]?.[verb]})`]));
    }
    return `${JSON.stringify(out, null, 2)}\n`;
  };
  const checkButton = el("button", { type: "button", className: "btn btn-ink" }, "Check against these answers");
  checkButton.addEventListener("click", () => check(entries(), json()));
  const downloadButton = el("button", { type: "button", className: "btn btn-line" }, "Download rls-probe.json");
  downloadButton.addEventListener("click", () => download("rls-probe.json", json()));

  return [
    ...(questions.length ? [el("div", { className: "grid gap-4" }, ...questions)] : [el("p", {}, answered ? "Every table has an answer. Change any of them below, then check again." : "Your code settles every table, so there's nothing to ask.")]),
    el("details", { className: "mt-5" }, el("summary", { className: "cursor-pointer font-semibold text-ink" }, answered ? `All the answers (${filled.length})` : `What rls-probe filled in from your code (${filled.length})`), el("div", { className: "mt-3 grid gap-4" }, ...filled)),
    el("div", { className: "mt-5 flex flex-wrap gap-3" }, checkButton, downloadButton),
    el("p", { className: "mt-3 text-[0.9rem] text-muted" }, "Save the file at the root of your repository, next to the supabase folder. From then on every inspection, here, in CI or in your coding agent, checks your database against it."),
  ];
}

// Applies answers to an inspection without probing again: the findings from before any
// declaration, checked against the new ones.
export function recheck(report, entries) {
  const base = report.undeclared ?? { findings: report.findings, accepted: report.accepted };
  const { findings, accepted, comparison } = applyAccess({ ...report, findings: base.findings }, entries);
  const order = { critical: 0, high: 1, medium: 2, review: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const next = { ...report, findings, accepted: [...base.accepted.filter((f) => !f.declared), ...accepted], access: { comparison, problems: [] } };
  Object.defineProperty(next, "undeclared", { value: base, enumerable: false });
  return next;
}

// A sentence's full stop, unless it already ends in one or a question mark.
function end(text) {
  return /[.?!]$/.test(text) ? text : `${text}.`;
}

function parse(text) {
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return {};
  }
}
