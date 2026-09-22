import express from "express";
import cors from "cors";
import db from "./db";

const app = express();
app.use(cors());
app.use(express.json());

// Get all past scans, most recent first
app.get("/api/scans", async (req, res) => {
  await db.read();
  const scans = [...db.data.scans].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );
  res.json(scans);
});

// Save a new scan result
app.post("/api/scans", async (req, res) => {
  const { filename, risk_tier, indicators, reported } = req.body;

  await db.read();
  const newScan = {
    id: db.data.nextId,
    filename,
    risk_tier,
    indicators: indicators || [],
    reported: !!reported,
    created_at: new Date().toISOString(),
  };
  db.data.scans.push(newScan);
  db.data.nextId += 1;
  await db.write();

  res.json({ id: newScan.id });
});

// Mark a scan as reported to IT Security
app.patch("/api/scans/:id/report", async (req, res) => {
  await db.read();
  const scan = db.data.scans.find((s) => s.id === Number(req.params.id));
  if (scan) {
    scan.reported = true;
    await db.write();
  }
  res.json({ success: true });
});

const PORT = 3001;
app.listen(PORT, () => console.log(`PhishScan API running on http://localhost:${PORT}`));
