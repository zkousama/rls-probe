// Which files of an app to read, chosen from their paths alone, the way the
// command line finds them: the migrations (supabase/migrations, then migrations,
// then a folder of .sql files, the shallowest first) and the code the scan reads.
// The web page uses it for a GitHub repository, a folder or a ZIP.
import { SKIP_DIRS, isCodeFile } from "./static.js";

// entries: [{ path, size? }] with "/" separated paths. stripTop: drop a single top
// folder shared by every path (a dropped folder, or a ZIP from GitHub).
// Returns null when there are no .sql files.
export function chooseFiles(entries, { stripTop = true, maxCodeFiles = 800, maxFileBytes = 2_000_000 } = {}) {
  let files = entries.filter((e) => !e.path.split("/").some((d) => SKIP_DIRS.has(d)));
  let top = "";
  if (stripTop) {
    const tops = new Set(files.map((e) => e.path.split("/")[0]));
    if (tops.size === 1 && files.every((e) => e.path.includes("/"))) top = `${[...tops][0]}/`;
  }
  files = files.map((e) => ({ ...e, rel: e.path.slice(top.length) }));
  const dirOf = (p) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
  const dirs = [...new Set(files.filter((e) => e.rel.endsWith(".sql")).map((e) => dirOf(e.rel)))];
  const shallowest = (list) => [...list].sort((a, b) => depth(a) - depth(b) || a.localeCompare(b))[0];
  const migrationsDir =
    shallowest(dirs.filter((d) => d === "supabase/migrations" || d.endsWith("/supabase/migrations"))) ??
    shallowest(dirs.filter((d) => d === "migrations" || d.endsWith("/migrations"))) ??
    shallowest(dirs);
  if (migrationsDir === undefined) return null;
  // The app's root: the folder holding supabase/migrations (or migrations).
  const named = /(^|\/)(supabase\/)?migrations$/.exec(migrationsDir);
  const root = named ? migrationsDir.slice(0, named.index) + named[1] : migrationsDir ? `${migrationsDir}/` : "";
  const priority = (p) => (p.startsWith("supabase/") ? 0 : /^\.env/.test(p.split("/").at(-1)) ? 1 : p.startsWith("src/") ? 2 : 3);
  const code = files
    .filter((e) => e.rel.startsWith(root) && isCodeFile(e.rel.slice(root.length)) && (e.size ?? 0) <= maxFileBytes)
    .map((e) => ({ ...e, rel: e.rel.slice(root.length) }))
    .sort((a, b) => priority(a.rel) - priority(b.rel) || a.rel.localeCompare(b.rel));
  return {
    root: top + root,
    // The app's rls-probe.json (see accept.js), if it has one.
    config: files.find((e) => e.rel === `${root}rls-probe.json`) ?? null,
    migrations: files.filter((e) => dirOf(e.rel) === migrationsDir && e.rel.endsWith(".sql")).sort((a, b) => a.rel.localeCompare(b.rel)),
    code: code.slice(0, maxCodeFiles),
    codeFilesFound: code.length,
  };
}

function depth(dir) {
  return dir ? dir.split("/").length : 0;
}
