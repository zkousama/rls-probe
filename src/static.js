import fs from "node:fs";
import path from "node:path";

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", ".turbo", ".vercel", "coverage", ".cache"]);
const EXTENSIONS = /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro|html|json)$|^\.env/;

// Keys that must never reach a browser. Anything in the front-end code or in a
// built bundle ships to every visitor.
const SECRETS = [
  { re: /sk_live_[0-9A-Za-z]{10,}/g, what: "Stripe live secret key" },
  { re: /rk_live_[0-9A-Za-z]{10,}/g, what: "Stripe restricted key" },
  { re: /sk-(proj-)?[A-Za-z0-9_-]{32,}/g, what: "OpenAI API key" },
  { re: /sk-ant-[A-Za-z0-9_-]{32,}/g, what: "Anthropic API key" },
  { re: /AKIA[0-9A-Z]{16}/g, what: "AWS access key" },
  { re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, what: "private key" },
  { re: /\b(VITE|NEXT_PUBLIC|PUBLIC|EXPO_PUBLIC)_[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE)[A-Z0-9_]*\b/g, what: "secret in a variable the build sends to the browser" },
];

export function scanFiles(root) {
  const findings = [];
  for (const file of walk(root)) {
    const rel = path.relative(root, file);
    let text;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (text.length > 5_000_000) continue;
    const lines = text.split("\n");
    lines.forEach((line, i) => {
      for (const jwt of line.match(/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g) ?? []) {
        const role = jwtRole(jwt);
        if (role === "service_role") {
          findings.push({ severity: "critical", where: `${rel}:${i + 1}`, title: "Supabase service role key in the code", detail: `${mask(jwt)} skips every access rule. Anyone who opens the site can copy it.` });
        }
      }
      for (const { re, what } of SECRETS) {
        for (const hit of line.match(re) ?? []) {
          if (/^\.env/.test(path.basename(file)) && what.startsWith("secret in a variable")) continue;
          findings.push({ severity: what.startsWith("secret in a variable") ? "high" : "critical", where: `${rel}:${i + 1}`, title: what, detail: mask(hit) });
        }
      }
    });
  }
  return findings.concat(scanFunctions(root));
}

// Edge functions with verify_jwt = false answer anyone. That's right for
// webhooks that check their own signature, and a hole for everything else.
function scanFunctions(root) {
  const config = path.join(root, "supabase", "config.toml");
  if (!fs.existsSync(config)) return [];
  const findings = [];
  let current = null;
  for (const line of fs.readFileSync(config, "utf8").split("\n")) {
    const header = /^\s*\[functions\.([\w-]+)\]/.exec(line);
    if (header) current = header[1];
    else if (/^\s*\[/.test(line)) current = null;
    else if (current && /^\s*verify_jwt\s*=\s*false/.test(line)) {
      const dir = path.join(root, "supabase", "functions", current);
      const source = readAll(dir);
      // A signed-in user, a webhook signature (Stripe, Svix, Supabase's own hooks through
      // standardwebhooks), or a shared secret in a header all count as checking.
      const checksCaller = /auth\.getUser|getClaims|Authorization|stripe\.webhooks\.constructEvent|constructEventAsync|x-signature|svix|verifySignature|standardwebhooks|new Webhook\(|timingSafeEqual|headers\.get\(\s*["'`]x-[\w-]*(secret|signature|token|key)["'`]/i.test(source);
      findings.push({
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

function* walk(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(path.join(dir, e.name));
    } else if (EXTENSIONS.test(e.name) && e.name !== "package-lock.json") {
      yield path.join(dir, e.name);
    }
  }
}

function readAll(dir) {
  return [...walk(dir)].map((f) => fs.readFileSync(f, "utf8")).join("\n");
}

function jwtRole(token) {
  try {
    return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8")).role;
  } catch {
    return null;
  }
}

function mask(secret) {
  return `${secret.slice(0, 8)}…${secret.slice(-4)}`;
}
