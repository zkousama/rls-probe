// Folders never scanned, and the files that are: front-end and function code,
// built bundles and env files. Shared with whatever gathers the files (node.js
// walks a folder; the web page reads a repository).
export const SKIP_DIRS = new Set(["node_modules", ".git", ".next", ".turbo", ".vercel", "coverage", ".cache"]);
const EXTENSIONS = /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro|html|json|py)$|^\.env/;
export const CONFIG = "supabase/config.toml";

// Whether a file, by its path relative to the app's root ("/" separated), is one
// the scan reads.
export function isCodeFile(file) {
  const parts = file.split("/");
  const name = parts.at(-1);
  if (parts.slice(0, -1).some((d) => SKIP_DIRS.has(d))) return false;
  return file === CONFIG || (EXTENSIONS.test(name) && name !== "package-lock.json");
}

// Keys that must never reach a browser. Anything in the front-end code or in a
// built bundle ships to every visitor.
const SECRETS = [
  { re: /sk_live_[0-9A-Za-z]{10,}/g, what: "Stripe live secret key" },
  { re: /rk_live_[0-9A-Za-z]{10,}/g, what: "Stripe restricted key" },
  // Project, service account and admin keys, or the older 48 characters after sk-. Other
  // services' sk- keys (sk-or-v1- for OpenRouter, sk-helicone-) aren't OpenAI's.
  { re: /\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,}|[A-Za-z0-9]{48}\b)/g, what: "OpenAI API key" },
  { re: /sk-ant-[A-Za-z0-9_-]{32,}/g, what: "Anthropic API key" },
  { re: /AKIA[0-9A-Z]{16}/g, what: "AWS access key" },
  // The key itself, not just its first line, which code that reads keys also contains.
  { re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----(?:\\n|\s)*[A-Za-z0-9+/]{40,}/g, what: "private key", nextLine: true },
  { re: /\b(VITE|NEXT_PUBLIC|PUBLIC|EXPO_PUBLIC)_[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE)[A-Z0-9_]*\b/g, what: "secret in a variable the build sends to the browser" },
];

// Tests and their fixtures: a key there is usually made up for the test. It never
// reaches a browser either, though a real one is still public in a public repository.
export const TEST_FILE = /(^|\/)(__tests__|__mocks__|tests?|spec|fixtures?|mocks?|e2e|cypress|playwright)\/|\.(test|spec|e2e)\.[cm]?[jt]sx?$|(^|\/)\.env\.([\w.-]*\.)?(example|sample|template|dist|defaults)$/;

// The keys every local Supabase (supabase start) prints: the same for everyone, and they
// open nothing but that local database. Docs and example files are full of them.
// Built from parts so secret scanners (GitHub's push protection) don't take this public
// key for a leaked one.
const LOCAL_SECRET = ["sb", "secret", "N7UND0UgjKTVK-Uodkm0Hg", "xSvEMPvz"].join("_");

// files: [{ path, text }], paths relative to the app's root.
export function scanCode(files) {
  const findings = [];
  for (const { path: rel, text } of files) {
    if (rel === CONFIG || !isCodeFile(rel) || text.length > 5_000_000) continue;
    const name = rel.split("/").at(-1);
    const test = TEST_FILE.test(rel);
    const lines = text.split("\n");
    lines.forEach((line, i) => {
      for (const jwt of line.match(/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g) ?? []) {
        const { role, iss } = jwtClaims(jwt);
        if (role === "service_role" && iss !== "supabase-demo") {
          findings.push({ kind: "service-key", key: "service_role", test, severity: test ? "review" : "critical", where: `${rel}:${i + 1}`, title: "Supabase service role key in the code", detail: `${mask(jwt)} skips every access rule. ${test ? "It's in a test file, so probably made up; if it's real, anyone who reads the repository can copy it." : "Anyone who opens the site can copy it."}` });
        }
      }
      // Supabase's newer secret keys aren't JWTs: sb_secret_ and a random string.
      for (const hit of (line.match(/\bsb_secret_[A-Za-z0-9_-]{20,}/g) ?? []).filter((k) => k !== LOCAL_SECRET)) {
        findings.push({ kind: "service-key", key: "secret", test, severity: test ? "review" : "critical", where: `${rel}:${i + 1}`, title: "Supabase secret key in the code", detail: `${mask(hit)} skips every access rule. ${test ? "It's in a test file, so probably made up; if it's real, anyone who reads the repository can copy it." : "Anyone who opens the site can copy it."}` });
      }
      // A form field's placeholder shows what a key looks like, not a key.
      if (/placeholder/i.test(line)) return;
      for (const { re, what, nextLine } of SECRETS) {
        // A key whose first line is here may go on to the next.
        if (nextLine && !line.includes("-----BEGIN")) continue;
        for (const hit of (nextLine ? `${line}\n${lines[i + 1] ?? ""}` : line).match(re) ?? []) {
          if (/^\.env/.test(name) && what.startsWith("secret in a variable")) continue;
          const browserVar = what.startsWith("secret in a variable");
          findings.push({ kind: browserVar ? "browser-secret" : "secret", ...(browserVar ? { variable: hit } : {}), test, severity: test ? "review" : browserVar ? "high" : "critical", where: `${rel}:${i + 1}`, title: what, detail: mask(hit) });
        }
      }
    });
  }
  return findings.concat(scanFunctions(files));
}

// Edge functions with verify_jwt = false answer anyone. That's right for
// webhooks that check their own signature, and a hole for everything else.
function scanFunctions(files) {
  const config = files.find((f) => f.path === CONFIG);
  if (!config) return [];
  const findings = [];
  let current = null;
  for (const line of config.text.split("\n")) {
    const header = /^\s*\[functions\.([\w-]+)\]/.exec(line);
    if (header) current = header[1];
    else if (/^\s*\[/.test(line)) current = null;
    else if (current && /^\s*verify_jwt\s*=\s*false/.test(line)) {
      const code = files.filter((f) => f.path.startsWith(`supabase/functions/${current}/`) && f.path !== CONFIG && isCodeFile(f.path));
      const source = code.map((f) => f.text).join("\n");
      // Configured, but its code isn't in the repository: nothing to judge.
      if (!code.length) {
        findings.push({ kind: "open-function", function: current, missing: true, severity: "review", where: `supabase/functions/${current}`, title: "Edge function open to anyone",
          detail: "verify_jwt is off, and its code isn't in the repository, so rls-probe can't tell whether it checks the caller or a signature." });
        continue;
      }
      // A signed-in user, a webhook signature (Stripe, Svix, Supabase's own hooks through
      // standardwebhooks), or a shared secret in a header all count as checking.
      const checksCaller = /auth\.getUser|getClaims|Authorization|stripe\.webhooks\.constructEvent|constructEventAsync|x-signature|svix|verifySignature|standardwebhooks|new Webhook\(|timingSafeEqual|headers\.get\(\s*["'`]x-[\w-]*(secret|signature|token|key)["'`]/i.test(source);
      findings.push({
        kind: "open-function",
        function: current,
        severity: checksCaller ? "review" : "high",
        where: `supabase/functions/${current}`,
        title: "Edge function open to anyone",
        detail: checksCaller
          ? "verify_jwt is off, but the code checks the caller or a signature. Worth a read to confirm."
          : "verify_jwt is off and the code doesn't check who's calling, so anyone on the internet can run it.",
      });
    }
  }
  return findings;
}

// The buckets supabase/config.toml declares, as [{ id, public }].
export function configBuckets(text) {
  const out = [];
  let current = null;
  for (const line of (text ?? "").split("\n")) {
    const header = /^\s*\[storage\.buckets\.([\w.-]+)\]/.exec(line);
    if (header) out.push((current = { id: header[1], public: false }));
    else if (/^\s*\[/.test(line)) current = null;
    else if (current && /^\s*public\s*=\s*true/.test(line)) current.public = true;
  }
  return out;
}

function jwtClaims(token) {
  try {
    const part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(part.padEnd(Math.ceil(part.length / 4) * 4, "=")));
  } catch {
    return {};
  }
}

function mask(secret) {
  return `${secret.slice(0, 8)}…${secret.slice(-4)}`;
}
