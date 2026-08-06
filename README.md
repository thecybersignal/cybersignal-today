# CyberSignal Today

A daily, public vulnerability-triage page for thecybersignal.com.

Pulls recent CVEs from NVD, cross-references the CISA KEV catalogue and FIRST EPSS
scores, matches them against stack archetypes, ranks them, folds in editorial takes
from a Google Sheet, and publishes a static page. No server, no database, no accounts.

## Setup

1. **Secrets** — repo Settings → Secrets and variables → Actions → New repository secret:
   - `NVD_API_KEY` — your activated NVD key
   - `SHEET_CSV_URL` — the published-to-web CSV URL of your `takes` tab

2. **Run it once by hand** — Actions tab → Build CyberSignal Today → Run workflow.
   Confirm `site/data.json` gets committed.

3. **Deploy** — Cloudflare Pages, connected to this repo, build output directory `site`.
   No build command needed; the files are already static.

## Daily routine

- 10:00 UTC the job runs and commits fresh data.
- Open the page, decide which items deserve a take.
- Write them into the Sheet: `date`, `item_id` (e.g. CVE-2026-4841), `your_take`, `publish` = yes.
- 12:00 UTC the job runs again and your notes appear on the page.

## Tuning

Almost all your editing happens in `scripts/segments.py`. Add keywords when a
product you care about is being missed; add a whole new archetype by copying an
existing block. Keywords are matched against NVD's CPE vendor/product strings and
the description text, so lowercase and underscores (`connect_secure`) work best.

`CUTLINE` controls what sits above the fold. Raise it if the page feels noisy,
lower it if it feels empty.

## Scoring

| Factor | Points |
|---|---|
| Listed in CISA KEV | +40 |
| Known ransomware use | +15 |
| Product is in the selected stack | +30 |
| EPSS exploit likelihood | 0–20 |
| CVSS base severity | 0–10 |

Every item on the page shows its own breakdown. That transparency is deliberate —
it is the part competitors ship as a black box.
