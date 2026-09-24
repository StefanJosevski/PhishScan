import { JSONFilePreset } from "lowdb/node";
import path from "path";
import { fileURLToPath } from "url";

export type Scan = {
  id: number;
  filename: string;
  risk_tier: string;
  indicators: string[];
  reported: boolean;
  created_at: string;
};

type Data = {
  scans: Scan[];
  nextId: number;
};

const defaultData: Data = { scans: [], nextId: 1 };

// Resolve the db file relative to THIS file's location, not the current
// working directory, so it's always written in the same place no matter
// which folder the server is started from.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbPath = path.join(__dirname, "..", "phishscan-db.json");

const db = await JSONFilePreset<Data>(dbPath, defaultData);

export default db;
