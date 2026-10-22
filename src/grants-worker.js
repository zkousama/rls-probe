import { parentPort, workerData } from "node:worker_threads";
import { grantsReport } from "./grants.js";
import { loadDatabase } from "./load.js";

// Builds the database without Supabase's old grants while the main thread
// probes, then sorts the tables once the probe's findings arrive.
const { db } = await loadDatabase(workerData.files, { grants: "explicit", snapshot: workerData.snapshot });
parentPort.once("message", async (findings) => parentPort.postMessage(await grantsReport(db, findings)));
