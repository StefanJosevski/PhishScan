import { JSONFilePreset } from "lowdb/node";

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

const db = await JSONFilePreset<Data>("phishscan-db.json", defaultData);

export default db;
