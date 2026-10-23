// Keeps every place that names rls-probe's version in step: package.json, the
// Claude Code plugin, its MCP server, its skill and the README.
//   node scripts/version.mjs set 0.5.0   updates them all
//   node scripts/version.mjs check [tag]  fails if any differ (or the tag, v0.5.0, doesn't match)
import fs from "node:fs";

const root = new URL("../", import.meta.url);
const read = (file) => fs.readFileSync(new URL(file, root), "utf8");
const write = (file, text) => fs.writeFileSync(new URL(file, root), text);

// Each file, and the versions it names.
const PLACES = [
  ["package.json", /^  "version": "([^"]+)"/m],
  ["plugin/.claude-plugin/plugin.json", /^  "version": "([^"]+)"/m],
  // The plugin's MCP server lives in plugin.json: a .mcp.json is often in global git ignores.
  ["plugin/.claude-plugin/plugin.json", /rls-probe@(\d+\.\d+\.\d+[\w.-]*)/g],
  ["plugin/skills/supabase-security/SKILL.md", /rls-probe@(\d+\.\d+\.\d+[\w.-]*)/g],
  ["README.md", /rls-probe@(\d+\.\d+\.\d+[\w.-]*)/g],
];

const [command, value] = process.argv.slice(2);
if (command === "set") {
  if (!/^\d+\.\d+\.\d+$/.test(value ?? "")) throw new Error("Usage: node scripts/version.mjs set 0.5.0");
  for (const [file, pattern] of PLACES) write(file, read(file).replace(pattern, (m, v) => m.replace(v, value)));
  console.log(`Set ${value} in ${PLACES.map(([f]) => f).join(", ")}.`);
} else if (command === "check") {
  const version = JSON.parse(read("package.json")).version;
  const wrong = [];
  for (const [file, pattern] of PLACES) {
    const found = [...read(file).matchAll(new RegExp(pattern.source, `${pattern.flags.replace("g", "")}g`))].map((m) => m[1]);
    if (!found.length) wrong.push(`${file}: names no version`);
    for (const v of found) if (v !== version) wrong.push(`${file}: ${v}`);
  }
  if (value && value !== `v${version}`) wrong.push(`tag ${value} (package.json says ${version})`);
  if (wrong.length) {
    console.error(`Versions don't match ${version}:\n  ${wrong.join("\n  ")}\nRun: node scripts/version.mjs set ${version}`);
    process.exit(1);
  }
  console.log(`All at ${version}.`);
} else {
  throw new Error("Usage: node scripts/version.mjs set 0.5.0 | check [tag]");
}
