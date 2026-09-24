import express from "express";
import cors from "cors";
import db, { type Scan } from "./db";

const app = express();
app.use(cors());
app.use(express.json());

type NewScanInput = {
  filename: string;
  risk_tier: string;
  indicators?: string[];
  reported?: boolean;
};

function isValidNewScan(body: any): body is NewScanInput {
  if (!body || typeof body !== "object") return false;
  if (typeof body.filename !== "string" || body.filename.trim() === "") return false;
  if (typeof body.risk_tier !== "string" || body.risk_tier.trim() === "") return false;
  if (body.indicators !== undefined && !Array.isArray(body.indicators)) return false;
  return true;
}

// Get all past scans, most recent first
app.get("/api/scans", async (req, res) => {
  try {
    await db.read();
    const scans = [...db.data.scans].sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
    res.json(scans);
  } catch (err) {
    console.error("GET /api/scans failed:", err);
    res.status(500).json({ error: "Failed to read scan history." });
  }
});

// Save a new scan result
app.post("/api/scans", async (req, res) => {
  if (!isValidNewScan(req.body)) {
    return res.status(400).json({
      error: "Invalid scan payload. 'filename' and 'risk_tier' are required strings, 'indicators' must be an array if provided.",
    });
  }

  const { filename, risk_tier, indicators, reported } = req.body as NewScanInput;

  try {
    await db.read();
    const newScan: Scan = {
      id: db.data.nextId,
      filename,
      risk_tier,
      indicators: indicators ?? [],
      reported: !!reported,
      created_at: new Date().toISOString(),
    };
    db.data.scans.push(newScan);
    db.data.nextId += 1;
    await db.write();

    res.status(201).json({ id: newScan.id });
  } catch (err) {
    console.error("POST /api/scans failed:", err);
    res.status(500).json({ error: "Failed to save scan." });
  }
});

// Mark a scan as reported to IT Security
app.patch("/api/scans/:id/report", async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid scan id." });
  }

  try {
    await db.read();
    const scan = db.data.scans.find((s) => s.id === id);

    if (!scan) {
      return res.status(404).json({ error: `Scan ${id} not found.` });
    }

    scan.reported = true;
    await db.write();

    res.json({ success: true, id: scan.id });
  } catch (err) {
    console.error("PATCH /api/scans/:id/report failed:", err);
    res.status(500).json({ error: "Failed to update scan." });
  }
});

const PORT = 3001;
app.listen(PORT, () => console.log(`PhishScan API running on http://localhost:${PORT}`));
