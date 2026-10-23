import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

// The page runs rls-probe's own modules (../src) and PGlite in the browser.
// SITE_BASE is /rls-probe/ on GitHub Pages; "/" locally or on a custom domain.
export default defineConfig({
  site: "https://zkousama.github.io",
  base: process.env.SITE_BASE ?? "/",
  outDir: "../_site",
  vite: {
    plugins: [tailwindcss()],
    optimizeDeps: { exclude: ["@electric-sql/pglite"] },
    server: { fs: { allow: [".."] } },
    build: { target: "es2022" },
  },
});
