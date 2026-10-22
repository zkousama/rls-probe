// Everything that needs Node: finding and reading the app's files, and the worker
// thread that builds the second database for --oct30. The rest of rls-probe runs
// in a browser too.
import fs from "node:fs";
import path from "node:path";
import { Worker } from "node:worker_threads";
import { SKIP_DIRS, isCodeFile } from "./static.js";

// The app's migrations: supabase/migrations, migrations, a folder of .sql files,
// or a single .sql file such as the output of `supabase db dump`.
export function findMigrations(target) {
  if (target.endsWith(".sql") && fs.existsSync(target) && fs.statSync(target).isFile()) return [target];
  const candidates = [path.join(target, "supabase", "migrations"), path.join(target, "migrations"), target];
  for (const dir of candidates) {
    if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
      const files = fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
      if (files.length) return files.map((f) => path.join(dir, f));
    }
  }
  return [];
}

export function readMigrations(files) {
  return files.map((file) => ({ name: path.basename(file), sql: fs.readFileSync(file, "utf8") }));
}

// The files the code scan reads, as [{ path, text }] with "/" separated paths.
export function readCodeFiles(root) {
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return [];
  const out = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) walk(full);
        continue;
      }
      const rel = path.relative(root, full).split(path.sep).join("/");
      if (!isCodeFile(rel)) continue;
      try {
        out.push({ path: rel, text: fs.readFileSync(full, "utf8") });
      } catch {
        // Unreadable: skipped, as before.
      }
    }
  };
  walk(root);
  return out;
}

// Starts the --oct30 check in a worker thread, which builds its own database
// without the old grants while the main thread probes. Returns the function that
// hands it the probe's findings and resolves to the report.
export function grantsInBackground(migrations, snapshot) {
  const worker = new Worker(new URL("./grants-worker.js", import.meta.url), { workerData: { migrations, snapshot } });
  const failed = new Promise((_, reject) => worker.once("error", reject));
  failed.catch(() => {}); // raised when the findings are handed over
  return (findings) => {
    worker.postMessage(findings);
    return Promise.race([failed, new Promise((resolve) => worker.once("message", resolve))]);
  };
}
