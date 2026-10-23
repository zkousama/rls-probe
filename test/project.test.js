import assert from "node:assert/strict";
import { test } from "node:test";
import { chooseFiles } from "../src/project.js";

const files = (...paths) => paths.map((path) => ({ path, size: 100 }));
const names = (list) => list.map((e) => e.rel);

test("a Lovable app: supabase/migrations, its code, and nothing from node_modules", () => {
  const chosen = chooseFiles(files(
    "supabase/migrations/2_b.sql", "supabase/migrations/1_a.sql", "supabase/config.toml",
    "supabase/functions/hook/index.ts", "src/App.tsx", ".env", "node_modules/x/index.js", "README.md",
  ), { stripTop: false });
  assert.equal(chosen.root, "");
  assert.deepEqual(names(chosen.migrations), ["supabase/migrations/1_a.sql", "supabase/migrations/2_b.sql"]);
  assert.deepEqual(names(chosen.code), ["supabase/config.toml", "supabase/functions/hook/index.ts", ".env", "src/App.tsx"]);
});

test("a ZIP from GitHub: the single top folder is dropped", () => {
  const chosen = chooseFiles(files("app-main/supabase/migrations/1.sql", "app-main/src/main.ts"));
  assert.deepEqual(names(chosen.migrations), ["supabase/migrations/1.sql"]);
  assert.deepEqual(names(chosen.code), ["src/main.ts"]);
});

test("a monorepo: supabase/migrations wins over another migrations folder, and code is the app's", () => {
  const chosen = chooseFiles(files("packages/db/migrations/1.sql", "apps/web/supabase/migrations/1.sql", "apps/web/src/a.ts", "apps/other/src/b.ts"), { stripTop: false });
  assert.equal(chosen.root, "apps/web/");
  assert.deepEqual(names(chosen.code), ["src/a.ts"]);
});

test("a folder of .sql files, or none at all", () => {
  const chosen = chooseFiles(files("sql/1_schema.sql", "sql/2_policies.sql", "sql/notes.txt"), { stripTop: false });
  assert.equal(chosen.root, "sql/");
  assert.deepEqual(names(chosen.migrations), ["sql/1_schema.sql", "sql/2_policies.sql"]);
  assert.equal(chooseFiles(files("src/a.ts", "README.md")), null);
});

test("code files are capped, supabase first, and oversized files skipped", () => {
  const many = files("supabase/migrations/1.sql", ...Array.from({ length: 5 }, (_, i) => `src/f${i}.ts`), "supabase/functions/x/index.ts");
  many.push({ path: "dist/huge.js", size: 5_000_000 });
  const chosen = chooseFiles(many, { stripTop: false, maxCodeFiles: 3 });
  assert.equal(chosen.codeFilesFound, 6);
  assert.deepEqual(names(chosen.code), ["supabase/functions/x/index.ts", "src/f0.ts", "src/f1.ts"]);
});
