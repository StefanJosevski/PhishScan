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

export type User = {
  id: number;
  name: string;
  email: string;
  passwordHash: string;
  role: string;
  avatar: string | null; // base64 data URL, or null for initials fallback
  totpSecret: string | null;
  totpEnabled: boolean;
  created_at: string;
};

type Data = {
  scans: Scan[];
  nextId: number;
  users: User[];
  nextUserId: number;
};

const defaultData: Data = { scans: [], nextId: 1, users: [], nextUserId: 1 };

// Resolve the db file relative to THIS file's location, not the current
// working directory, so it's always written in the same place no matter
// which folder the server is started from.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbPath = path.join(__dirname, "..", "phishscan-db.json");

const db = await JSONFilePreset<Data>(dbPath, defaultData);

// If the db file already exists from before users were added, backfill
// the new fields so old data doesn't crash routes that expect them.
db.data.users ??= [];
db.data.nextUserId ??= 1;
for (const u of db.data.users) {
  if (u.totpSecret === undefined) u.totpSecret = null;
  if (u.totpEnabled === undefined) u.totpEnabled = false;
}
await db.write();

export default db;

