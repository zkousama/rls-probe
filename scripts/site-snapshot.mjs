// Writes the base database the web page starts from into site/public/.
import fs from "node:fs";
import zlib from "node:zlib";
import { buildSnapshot } from "../src/snapshot.js";

const out = new URL("../site/public/base.tar.gz", import.meta.url);
fs.mkdirSync(new URL(".", out), { recursive: true });
fs.writeFileSync(out, zlib.gzipSync(await buildSnapshot(), { level: 9 }));
console.log("Wrote site/public/base.tar.gz");
