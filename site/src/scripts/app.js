// The page: reads an app from a GitHub link, a folder, a ZIP or pasted SQL, runs
// rls-probe on it in this browser, and shows the inspection.
import { explain, fixPrompt } from "../../../src/explain.js";
import { renderGrants } from "../../../src/grants.js";
import { chooseFiles } from "../../../src/project.js";
import { renderText } from "../../../src/report.js";
import { SKIP_DIRS } from "../../../src/static.js";

const $ = (id) => document.getElementById(id);
const BASE = import.meta.env.BASE_URL;
const MAX_CODE_FILES = 800;
const MAX_FILE_BYTES = 2_000_000;
const SAMPLE = "https://github.com/zkousama/rls-probe/tree/main/test/fixtures/leaky";

// A problem with what was given, said to the person, as opposed to a bug.
class Problem extends Error {}

// The probe, Postgres and the base database: about 20 MB, fetched once someone
// starts, so reading the page costs nothing.
let warm;
function warmUp() {
  warm ??= Promise.all([fetch(`${BASE}base.tar.gz`).then((r) => r.blob()), import("../../../src/engine.js")]);
  return warm;
}
for (const event of ["pointerdown", "focusin", "dragenter"]) document.addEventListener(event, warmUp, { once: true });

// ---------- Choosing where the app is ----------
const tabs = [...document.querySelectorAll('[role="tab"]')];
for (const tab of tabs) tab.addEventListener("click", () => select(tab));
tabs[0].parentElement.addEventListener("keydown", (e) => {
  const i = tabs.indexOf(document.activeElement);
  if (i < 0 || !["ArrowLeft", "ArrowRight"].includes(e.key)) return;
  const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
  select(next);
  next.focus();
});
function select(tab) {
  for (const t of tabs) {
    const on = t === tab;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
    $(t.getAttribute("aria-controls")).hidden = !on;
  }
}

let again = null;
$("pane-github").addEventListener("submit", (e) => {
  e.preventDefault();
  const url = $("repo").value;
  inspect(() => fromGitHub(url));
});
$("example").addEventListener("click", () => {
  $("repo").value = SAMPLE;
  $("pane-github").requestSubmit();
});
$("pane-sql").addEventListener("submit", (e) => {
  e.preventDefault();
  const sql = $("sql").value;
  inspect(async () => ({ label: "your pasted SQL", migrations: [{ name: "schema.sql", sql }], code: [] }));
});
$("pick-folder").addEventListener("click", () => $("files").click());
$("pick-zip").addEventListener("click", () => $("zip").click());
$("files").addEventListener("change", (e) => {
  const list = [...e.target.files].map((f) => ({ path: f.webkitRelativePath || f.name, size: f.size, read: () => f.text() }));
  inspect(async () => fromEntries(list, "your folder"));
});
$("zip").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) inspect(async () => fromEntries(await readZip(file), file.name));
});
const drop = $("drop");
drop.addEventListener("dragover", (e) => {
  e.preventDefault();
  drop.classList.add("over");
});
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  const items = [...e.dataTransfer.items].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  const file = e.dataTransfer.files[0];
  if (items.length === 1 && items[0].isFile && /\.zip$/i.test(items[0].name)) inspect(async () => fromEntries(await readZip(file), file.name));
  else inspect(async () => fromEntries(await walkEntries(items), items.length === 1 ? items[0].name : "your files"));
});

// ---------- Reading an app ----------

// A GitHub link: github.com/owner/repo, optionally /tree/branch/folder.
async function fromGitHub(input) {
  const s = input.trim().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\.git$/, "").replace(/\/+$/, "");
  const m = /^(?:github\.com\/)?([\w.-]+)\/([\w.-]+)(?:\/tree\/([^/]+)(?:\/(.+))?)?$/.exec(s);
  if (!m) throw new Problem("That isn't a GitHub repository link. It should look like https://github.com/you/your-app.");
  const [, owner, repo, branch, dir] = m;
  const api = async (url) => {
    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}${url}`, { headers: { Accept: "application/vnd.github+json" } });
    if (res.status === 404) throw new Problem(`github.com/${owner}/${repo} wasn't found. If it's private, download it and choose Folder or ZIP.`);
    if (res.status === 403 || res.status === 429) throw new Problem("GitHub's limit for visitors without an account is used up for now. Try again in an hour, or download the repository and choose Folder or ZIP.");
    if (!res.ok) throw new Problem(`GitHub answered ${res.status}. Try again, or choose Folder or ZIP.`);
    return res.json();
  };
  const ref = branch ?? (await api("")).default_branch;
  const tree = await api(`/git/trees/${encodeURIComponent(ref)}?recursive=1`);
  const prefix = dir ? `${dir}/` : "";
  const entries = tree.tree
    .filter((t) => t.type === "blob" && t.path.startsWith(prefix))
    .map((t) => ({
      path: t.path.slice(prefix.length),
      size: t.size,
      read: async () => {
        const res = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(ref)}/${t.path.split("/").map(encodeURIComponent).join("/")}`);
        if (!res.ok) throw new Problem(`${t.path} couldn't be read from GitHub (${res.status}).`);
        return res.text();
      },
    }));
  const project = await fromEntries(entries, `github.com/${owner}/${repo}${dir ? `/${dir}` : ""}`, false);
  if (tree.truncated) project.note = "The repository is very large, so GitHub listed only part of it.";
  return project;
}

// Files as [{ path, size, read }]: picks the migrations and the code the scan
// reads (see src/project.js), then reads only those.
async function fromEntries(all, label, stripTop = true) {
  const chosen = chooseFiles(all, { stripTop, maxCodeFiles: MAX_CODE_FILES, maxFileBytes: MAX_FILE_BYTES });
  if (!chosen) {
    throw new Problem("There are no database migrations here: no supabase/migrations folder and no .sql files. If your tables were made in the Supabase dashboard, there's nothing to inspect yet.");
  }
  const sqls = await readAll(chosen.migrations);
  const texts = await readAll(chosen.code);
  return {
    label,
    migrations: chosen.migrations.map((e, i) => ({ name: e.rel.split("/").at(-1), sql: sqls[i] })),
    code: chosen.code.map((e, i) => ({ path: e.rel, text: texts[i] })),
    note: chosen.codeFilesFound > chosen.code.length ? `The first ${chosen.code.length} of ${chosen.codeFilesFound} code files were scanned.` : "",
  };
}

async function readAll(entries, parallel = 12) {
  const out = new Array(entries.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(parallel, entries.length) }, async () => {
    while (next < entries.length) {
      const i = next++;
      out[i] = await entries[i].read();
    }
  }));
  return out;
}

// A dropped folder, through the File and Directory Entries API.
async function walkEntries(items) {
  const out = [];
  const walk = async (entry, prefix) => {
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      out.push({ path: prefix + entry.name, size: file.size, read: () => file.text() });
    } else if (entry.isDirectory && !SKIP_DIRS.has(entry.name)) {
      const reader = entry.createReader();
      for (;;) {
        const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
        if (!batch.length) break;
        for (const child of batch) await walk(child, `${prefix}${entry.name}/`);
      }
    }
  };
  for (const item of items) await walk(item, "");
  return out;
}

// A ZIP, read with the browser's own decompression (no library).
async function readZip(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  const view = new DataView(buf.buffer);
  let end = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      end = i;
      break;
    }
  }
  if (end < 0) throw new Problem("That file isn't a ZIP, or it's damaged.");
  const count = view.getUint16(end + 10, true);
  if (count === 0xffff) throw new Problem("That ZIP is too large to read here. Unzip it and drop the folder instead.");
  const names = new TextDecoder();
  const entries = [];
  let p = view.getUint32(end + 16, true);
  for (let n = 0; n < count && view.getUint32(p, true) === 0x02014b50; n++) {
    const method = view.getUint16(p + 10, true);
    const compressed = view.getUint32(p + 20, true);
    const size = view.getUint32(p + 24, true);
    const nameLength = view.getUint16(p + 28, true);
    const local = view.getUint32(p + 42, true);
    const path = names.decode(buf.subarray(p + 46, p + 46 + nameLength));
    p += 46 + nameLength + view.getUint16(p + 30, true) + view.getUint16(p + 32, true);
    if (path.endsWith("/")) continue;
    entries.push({
      path,
      size,
      read: async () => {
        const start = local + 30 + view.getUint16(local + 26, true) + view.getUint16(local + 28, true);
        const data = buf.subarray(start, start + compressed);
        if (method === 0) return new TextDecoder().decode(data);
        if (method === 8) return new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).text();
        throw new Problem(`${path} uses a compression this page can't read. Unzip it and drop the folder instead.`);
      },
    });
  }
  return entries;
}

// ---------- Inspecting ----------
const STEPS = [
  ["read", "Reading your files", "Fetching your migrations and code."],
  ["start", "Starting Postgres in this browser", "About 20 MB, downloaded once."],
  ["migrations", "Rebuilding your database from its migrations", "Running each migration the way Supabase does."],
  ["seed", "Moving in two test users", "Giving each of them rows in every table."],
  ["probe", "Trying every table as a visitor and as the other user", "Seeing, changing, deleting and adding the first user's rows."],
  ["grants", "Checking Supabase's October 30 change", "Which tables need grants, and which grants are safe."],
];

async function inspect(source) {
  again = () => inspect(source);
  for (const b of document.querySelectorAll("button")) b.disabled = true;
  $("error").hidden = true;
  $("result").hidden = true;
  showSteps("read");
  $("progress").scrollIntoView({ behavior: "smooth", block: "center" });
  try {
    const project = await source();
    showSteps("start");
    const [snapshot, { runProbe }] = await warmUp();
    const report = await runProbe({ ...project, oct30: true, snapshot, onProgress: showSteps });
    $("progress").hidden = true;
    show(report, project);
  } catch (error) {
    $("progress").hidden = true;
    $("error").textContent = error instanceof Problem ? error.message : `The inspection stopped: ${error.message}. If this keeps happening, open an issue on GitHub with the link you used.`;
    $("error").hidden = false;
    if (!(error instanceof Problem)) console.error(error);
  } finally {
    for (const b of document.querySelectorAll("button")) b.disabled = false;
  }
}

function showSteps(now) {
  const at = STEPS.findIndex(([key]) => key === now);
  $("progress").querySelector(".steps").replaceChildren(...STEPS.map(([, text], i) => el("li", { className: i < at ? "done" : i === at ? "now" : "" }, text)));
  $("progress-sub").textContent = STEPS[at]?.[2] ?? "";
  $("progress").hidden = false;
}

// ---------- The inspection slip ----------
const SEVERITY = { critical: "Critical", high: "High", medium: "Medium", review: "Worth checking" };

function show(report, project) {
  const e = explain(report);
  const tables = report.results.length;
  const count = (severity) => e.problems.filter((p) => p.severity === severity).length;
  const fixable = e.problems.length || e.grants?.lines.length;

  const title = !tables ? "Nothing to inspect"
    : e.problems.length ? `${e.problems.length} problem${e.problems.length === 1 ? "" : "s"} to fix`
    : e.notes.length || e.grants?.lines.length ? "No problems, a few things to check" : "No problems found";
  const tally = [...["critical", "high", "medium"].filter(count).map((s) => `${count(s)} ${SEVERITY[s].toLowerCase()}`), ...(e.notes.length ? [`${e.notes.length} worth checking`] : [])];

  const actions = el("div", { className: "mt-5 flex flex-wrap gap-3" });
  if (fixable) actions.append(copyButton("Copy the fix for your AI builder", fixPrompt(report), "btn btn-ink"));
  const rerun = el("button", { type: "button", className: "btn btn-line" }, "Inspect again");
  rerun.addEventListener("click", () => again?.());
  actions.append(rerun);

  const head = el("div", { className: "slip-head" },
    el("div", { className: `placard stamp grade-${e.grade ?? "none"}`, role: "img", ariaLabel: e.grade ? `Grade ${e.grade}` : "No grade" },
      el("span", { className: "p-title" }, "Database inspection"),
      el("span", { className: "p-letter" }, e.grade ?? "?"),
      el("span", { className: "p-sub" }, `${tables} table${tables === 1 ? "" : "s"} checked`),
    ),
    el("div", { className: "min-w-0" },
      el("h2", { className: "text-[clamp(1.5rem,3vw,2.1rem)] leading-tight font-extrabold text-ink [font-stretch:115%]" }, title),
      el("p", { className: "mt-1 text-text [overflow-wrap:anywhere]" }, !tables ? "The migrations create no tables, so this is not an all clear." : `Inspection of ${project.label}.${tally.length ? ` ${capitalize(tally.join(", "))}.` : ""}`),
      ...(project.note ? [el("p", { className: "mt-1 text-[0.95rem] text-muted" }, project.note)] : []),
      actions,
      ...(fixable ? [el("p", { className: "mt-3 text-[0.95rem] text-muted" }, "Paste the fix into Lovable, Bolt, Cursor or Claude. When your app is updated, inspect it again.")] : []),
    ),
  );

  const sections = [];
  if (e.problems.length) {
    sections.push(section("Problems", null, el("div", {}, ...e.problems.map((p) => el("div", { className: "finding" },
      el("span", { className: `sev sev-${p.severity}` }, SEVERITY[p.severity]),
      el("div", {},
        el("p", { className: "font-semibold" }, p.headline),
        el("details", { className: "mt-1.5" }, el("summary", {}, "What to change"), el("p", { className: "ask" }, p.ask), ...yourself(p)),
      ),
    )))));
  }
  if (report.results.length) sections.push(checklist(report));
  if (e.grants) {
    const body = [el("p", {}, e.grants.summary)];
    if (e.grants.lines.length) body.push(el("p", { className: "mt-3 text-[0.95rem] text-muted" }, "Add these lines to a new migration, or let the fix above do it:"), el("pre", { className: "codebox" }, e.grants.lines.join("\n")), copyButton("Copy the grants", `${e.grants.lines.join("\n")}\n`, "btn btn-line"));
    sections.push(section("After October 30", null, ...body));
  }
  if (e.notes.length) {
    sections.push(section("Worth checking", "Fine if they're on purpose.", el("div", {}, ...e.notes.map((n) => el("div", { className: "finding" },
      el("span", { className: "sev sev-review" }, "Check"),
      el("div", {}, el("p", {}, n.headline), el("details", { className: "mt-1.5" }, el("summary", {}, "If it isn't on purpose"), el("p", { className: "ask" }, n.ask), ...yourself(n))),
    )))));
  }
  if (e.missing.length) {
    const named = e.missing.length > 1 ? `${e.missing.slice(0, -1).join(", ")} and ${e.missing.at(-1)}` : e.missing[0];
    sections.push(section("Not inspected", null, el("p", {}, `Your migrations use ${named} but never create ${e.missing.length === 1 ? "it" : "them"}, so ${e.missing.length === 1 ? "it wasn't" : "they weren't"} inspected. Were ${e.missing.length === 1 ? "it" : "they"} made in the Supabase dashboard?`)));
  }
  sections.push(el("section", { className: "slip-section" }, el("details", {},
    el("summary", { className: "cursor-pointer font-bold text-ink" }, "Full technical report"),
    el("pre", { className: "codebox" }, renderText({ ...report, target: project.label }) + (report.grantsChange ? renderGrants(report.grantsChange) : "")),
  )));

  $("result").replaceChildren(el("div", { className: "slip mt-4" }, head, ...sections));
  $("result").hidden = false;
  $("result").scrollIntoView({ behavior: "smooth", block: "start" });
}

// Every table, and what a visitor and a second signed-in user managed to do to the
// first user's rows. Tables with the most reached cells come first.
function checklist(report) {
  const ACTIONS = [["read", "see"], ["update", "change"], ["delete", "delete"], ["insert", "add"]];
  const state = (r, who, action) => {
    const reached = action === "read" ? r[who].read > 0 : r[who][action];
    if (!reached) return "blocked";
    return r.owned || action !== "read" ? "reached" : "public";
  };
  const MARK = { reached: "✗", public: "○", blocked: "✓" };
  const WORD = { reached: "reached", public: "readable, shared table", blocked: "blocked" };
  const probed = report.results.filter((r) => r.anon);
  const reached = (r) => ["anon", "B"].flatMap((who) => ACTIONS.map(([a]) => state(r, who, a))).filter((s) => s === "reached").length;
  const rows = [...probed].sort((a, b) => reached(b) - reached(a) || a.table.localeCompare(b.table));
  const mark = (r, who, a, label, first) => {
    const s = state(r, who, a);
    return el("td", { className: first ? "gap" : "" }, el("span", { className: `mark mark-${s}`, title: `${who === "anon" ? "A visitor" : "Another user"}, ${label}: ${WORD[s]}`, ariaLabel: `${label}: ${WORD[s]}` }, MARK[s]));
  };
  const table = el("table", { className: "checklist" },
    el("thead", {},
      el("tr", {}, el("th", {}), el("th", { colSpan: 4, className: "who gap" }, "A visitor"), el("th", { colSpan: 4, className: "who gap" }, "Another signed-in user")),
      el("tr", {}, el("th", {}), ...["anon", "B"].flatMap(() => ACTIONS.map(([, label], i) => el("th", { className: i === 0 ? "gap" : "" }, label)))),
    ),
    el("tbody", {},
      ...rows.map((r) => el("tr", {},
        el("td", { className: "table-name" }, r.table, ...(r.rls ? [] : [el("span", { className: "flag" }, "RLS off")]), ...(r.owned ? [] : [el("span", { className: "flag shared" }, "shared")])),
        ...["anon", "B"].flatMap((who) => ACTIONS.map(([a, label], i) => mark(r, who, a, label, i === 0))),
      )),
      ...report.results.filter((r) => !r.anon).map((r) => el("tr", {}, el("td", { className: "table-name" }, r.table), el("td", { colSpan: 8, className: "gap text-left text-[0.88rem] text-muted" }, `Not tested: ${r.skipped}`))),
    ),
  );
  return section("Who could reach your users' rows", "Each table held rows belonging to a test user. This is what the others managed to do to them.",
    el("div", { className: "-mx-1 overflow-x-auto px-1" }, table),
    el("p", { className: "mt-4 flex flex-wrap gap-x-6 gap-y-1 text-[0.9rem] text-muted" },
      el("span", {}, el("span", { className: "mark mark-reached" }, "✗"), "reached another user's data"),
      el("span", {}, el("span", { className: "mark mark-public" }, "○"), "readable, in a table everyone shares"),
      el("span", {}, el("span", { className: "mark mark-blocked" }, "✓"), "blocked"),
    ),
  );
}

// The same change as a step to take yourself, for people who run their own Supabase
// project (a Lovable Cloud project has no Supabase dashboard).
function yourself(item) {
  if (!item.selfFix) return [];
  const where = item.selfFix.where === "SQL Editor" ? "in the SQL Editor, run" : `in ${item.selfFix.where}`;
  return [
    el("p", { className: "mt-3 text-[0.92rem] text-muted" }, `Or, if you manage your own Supabase project, ${where}:`),
    el("pre", { className: "codebox" }, item.selfFix.code),
    copyButton("Copy", item.selfFix.code, "btn btn-line h-9 px-3 text-[0.9rem]"),
  ];
}

function section(title, lead, ...body) {
  return el("section", { className: "slip-section" },
    el("h3", {}, title),
    ...(lead ? [el("p", { className: "mb-2 text-[0.95rem] text-muted" }, lead)] : []),
    ...body,
  );
}

function copyButton(label, text, className) {
  const button = el("button", { type: "button", className }, label);
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = el("textarea", {}, text);
      document.body.append(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = label), 2000);
  });
  return button;
}

// Elements are built with text nodes only: names from the repository never become HTML.
function el(tag, props, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function capitalize(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
