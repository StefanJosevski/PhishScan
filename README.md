# PhishScan

**PhishScan** is a phishing detection application designed to give non-technical employees a fast, reliable way to check whether an email, file, or link is safe, without needing any security background. Users upload a suspicious email, document, or screenshot, or paste raw email text, and PhishScan analyzes it for phishing indicators, then returns a clear risk verdict along with a plain-language explanation of what was found and exactly what to do next.

Built as a UX Design case study project, PhishScan focuses on solving the real gap in most organizations: employees are trained to *recognize* phishing, but rarely report it because the process is confusing, buried in menus, or requires technical know-how. PhishScan is designed to remove that friction entirely.

---

## The Problem

Phishing remains one of the most common entry points for security breaches. Reporting, not recognition, is usually where prevention fails, existing "report phishing" tools are often hidden several menus deep or require filling out a confusing form. PhishScan is built to make both detection and reporting fast, clear, and accessible to everyone, regardless of technical skill or age.

## Target Audience

Everyday, non-technical employees across a wide range of ages and abilities, deliberately designed to be usable by someone as young as 20 with strong vision and someone as old as 70 with low vision or reduced dexterity. Accessibility is a core design requirement, not an afterthought.

---

## Key Features

- **Three-tier risk system** — High Risk, Suspicious, and No Threats Detected, instead of a binary "Safe/Unsafe" label, to avoid giving users false confidence
- **Action-first results** — every result leads with what the user should do, with supporting detection details underneath
- **Plain-language explanations** — technical terms like SPF, DKIM, and DMARC are translated into everyday language, with an option to expand and view technical details
- **Post-risk follow-up** — for high-risk results, users are asked whether they already interacted with the email (clicked a link, downloaded a file, entered information) and given tailored next steps
- **One-click reporting** — reporting a phishing email to IT Security takes a single click, with a clear confirmation shown immediately after
- **Scan history** — a running log of past scans with filenames, risk tiers, and timestamps
- **Accessibility settings** — adjustable text size (Standard / Large / Extra Large), a High Contrast mode, and a Reduce Motion toggle

---

## Tech Stack

- **Frontend:** React + TypeScript + Vite
- **Styling:** Tailwind CSS
- **Backend:** Express (Node.js)
- **Database:** lowdb (lightweight JSON-file database, no native dependencies required)
- **Design:** Figma / Figma Make

---

## Getting Started

### 1. Install dependencies
```bash
npm install
```

### 2. Run the frontend
```bash
npm run dev
```
The app will be available at `http://localhost:5173`.

### 3. Run the backend
In a separate terminal:
```bash
npm run server
```
The API will be available at `http://localhost:3001`.

Both need to be running at the same time for the full app to work end-to-end.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/scans` | Returns all past scans, most recent first |
| `POST` | `/api/scans` | Saves a new scan result |
| `PATCH`| `/api/scans/:id/report` | Marks a scan as reported to IT Security |

---

## Project Structure

```
PhishScan_web_application_design/
├── src/
│   ├── App.tsx          # Main application (screens, state, UI logic)
│   ├── index.css        # Global styles
│   └── main.tsx         # App entry point
├── server/
│   ├── db.ts             # lowdb database setup
│   └── index.ts          # Express API server
├── package.json
└── README.md
```

---

## Team

This project was built as a group project for a User Experience Design course. Roles were divided across Figma design and front-end development, API integration, database and backend, user research and personas, and accessibility/QA.

---

## Roadmap

- [ ] Connect frontend to backend API (replace mock scan data with real requests)
- [ ] Integrate a real threat-intelligence API (VirusTotal or Google Safe Browsing) for link checking
- [ ] Add AI-assisted analysis for email content and plain-language explanations
- [ ] Implement real user authentication
- [ ] Mobile-responsive layout
- [ ] Full WCAG accessibility audit
- [ ] Usability testing across a range of age groups
