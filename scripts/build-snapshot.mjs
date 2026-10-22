// Builds the base database shipped with the package, so a first run, or one in
// CI, starts as fast as one with a warm cache. npm runs this before packing.
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";
import { SHIPPED, buildSnapshot } from "../src/snapshot.js";

const dir = new URL("../snapshot/", import.meta.url);
fs.rmSync(dir, { recursive: true, force: true });
fs.mkdirSync(dir);
fs.writeFileSync(SHIPPED, zlib.gzipSync(await buildSnapshot(), { level: 9 }));
console.log(`Wrote ${fileURLToPath(SHIPPED)}`);
