"""
CyberSignal Today -- daily build.

Pulls recent CVEs from NVD, cross-references CISA KEV and FIRST EPSS,
matches everything against the stack archetypes in segments.py, scores it,
folds in your editorial takes from the published Google Sheet, and writes
site/data.json for the static page.

Reads two environment variables:
    NVD_API_KEY    -- your NVD key (required)
    SHEET_CSV_URL  -- the published-to-web CSV URL of your takes tab (optional)

Run locally:  NVD_API_KEY=xxx python scripts/build.py
"""

import csv
import io
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from segments import SEGMENTS, CUTLINE, ITEMS_PER_SEGMENT

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "site" / "data.json"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "72"))
UA = {"User-Agent": "CyberSignal-Today/1.0 (+https://thecybersignal.com)"}


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------

def fetch_kev():
    """Return {cve_id: {...}} for everything CISA lists as actively exploited."""
    r = requests.get(KEV_URL, headers=UA, timeout=60)
    r.raise_for_status()
    out = {}
    for v in r.json().get("vulnerabilities", []):
        out[v["cveID"]] = {
            "added": v.get("dateAdded"),
            "action": v.get("requiredAction", ""),
            "due": v.get("dueDate"),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown") == "Known",
        }
    print(f"  KEV entries: {len(out)}")
    return out


def fetch_nvd(api_key, hours):
    """Return a list of raw NVD vulnerability records modified in the window."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    fmt = "%Y-%m-%dT%H:%M:%S.000"

    headers = dict(UA)
    if api_key:
        headers["apiKey"] = api_key

    results, index = [], 0
    while True:
        params = {
            "lastModStartDate": start.strftime(fmt),
            "lastModEndDate": end.strftime(fmt),
            "resultsPerPage": 2000,
            "startIndex": index,
        }
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=90)
        if r.status_code == 403:
            raise SystemExit(
                "NVD returned 403. Your API key is missing, wrong, or not activated."
            )
        r.raise_for_status()
        data = r.json()
        batch = data.get("vulnerabilities", [])
        results.extend(batch)
        total = data.get("totalResults", 0)
        index += len(batch)
        print(f"  NVD {index}/{total}")
        if index >= total or not batch:
            break
        time.sleep(0.8)  # stay well inside the rate limit
    return results


def fetch_epss(cve_ids):
    """Return {cve_id: probability}. Batched -- the API takes comma-separated IDs."""
    scores = {}
    ids = list(cve_ids)
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        try:
            r = requests.get(
                EPSS_URL, params={"cve": ",".join(chunk)}, headers=UA, timeout=60
            )
            r.raise_for_status()
            for row in r.json().get("data", []):
                scores[row["cve"]] = float(row.get("epss", 0))
        except Exception as e:
            print(f"  EPSS batch failed, continuing without it: {e}")
        time.sleep(0.3)
    print(f"  EPSS scores: {len(scores)}")
    return scores


def fetch_takes(csv_url):
    """Return {item_id: take} for rows where publish is yes."""
    if not csv_url:
        print("  No SHEET_CSV_URL set -- building without editorial takes.")
        return {}
    try:
        r = requests.get(csv_url, headers=UA, timeout=45)
        r.raise_for_status()
        reader = csv.DictReader(io.StringIO(r.text))
        takes = {}
        for row in reader:
            row = { (k or "").strip().lower(): (v or "").strip()
                    for k, v in row.items() }
            if row.get("publish", "").lower() in ("yes", "y", "true", "1"):
                if row.get("item_id") and row.get("your_take"):
                    takes[row["item_id"].upper()] = row["your_take"]
        print(f"  Editorial takes: {len(takes)}")
        return takes
    except Exception as e:
        print(f"  Could not read the Sheet, continuing without takes: {e}")
        return {}


# --------------------------------------------------------------------------
# parsing, matching, scoring
# --------------------------------------------------------------------------

def parse_cve(record):
    """Flatten one NVD record into the fields we care about."""
    c = record.get("cve", {})
    cve_id = c.get("id", "")

    desc = ""
    for d in c.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if desc.startswith("Rejected reason") or "** REJECT" in desc.upper():
        return None

    cvss, vector = 0.0, ""
    metrics = c.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            d = metrics[key][0].get("cvssData", {})
            cvss = float(d.get("baseScore", 0) or 0)
            vector = d.get("vectorString", "")
            break

    cpes = set()
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria", "")
                parts = crit.split(":")
                if len(parts) > 5:
                    cpes.add(f"{parts[3]}:{parts[4]}")

    return {
        "id": cve_id,
        "desc": desc,
        "cvss": cvss,
        "vector": vector,
        "cpes": sorted(cpes),
        "published": c.get("published", ""),
        "modified": c.get("lastModified", ""),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def match_segments(item):
    """Which stack archetypes does this CVE touch?"""
    haystack = " ".join(item["cpes"]).lower() + " " + item["desc"].lower()
    hits = []
    for seg_id, seg in SEGMENTS.items():
        for kw in seg["keywords"]:
            if kw in haystack:
                hits.append(seg_id)
                break
    return hits


def score(item, kev_entry, epss, in_segment):
    """Return (total, factors). Every factor is shown to the reader."""
    factors = []
    if kev_entry:
        factors.append({"label": "Listed as actively exploited", "points": 40})
        if kev_entry.get("ransomware"):
            factors.append({"label": "Used in ransomware campaigns", "points": 15})
    if in_segment:
        factors.append({"label": "Runs in this environment", "points": 30})
    if epss > 0:
        factors.append({
            "label": f"Exploit likelihood {epss:.2f}",
            "points": round(epss * 20),
        })
    if item["cvss"] > 0:
        factors.append({
            "label": f"Severity {item['cvss']:.1f}",
            "points": round(item["cvss"]),
        })
    return sum(f["points"] for f in factors), factors


def headline(item):
    """First sentence of the description, trimmed to something readable."""
    text = item["desc"].split(". ")[0].strip().rstrip(".")
    return (text[:157] + "...") if len(text) > 160 else text


def vendors(item):
    out = []
    for cpe in item["cpes"][:4]:
        vendor, product = cpe.split(":", 1)
        out.append(product.replace("_", " "))
    return sorted(set(out))


# --------------------------------------------------------------------------

def main():
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    sheet_url = os.environ.get("SHEET_CSV_URL", "").strip()
    if not api_key:
        print("WARNING: NVD_API_KEY is not set. Falling back to unauthenticated "
              "requests, which are heavily rate limited.")

    print("Fetching...")
    kev = fetch_kev()
    raw = fetch_nvd(api_key, LOOKBACK_HOURS)
    takes = fetch_takes(sheet_url)

    items = [p for p in (parse_cve(r) for r in raw) if p]
    scanned = len(items)
    print(f"  Parsed {scanned} usable CVEs")

    # Only look up EPSS for things that could plausibly matter -- keeps the
    # API calls down by an order of magnitude.
    candidates = [i for i in items if i["cvss"] >= 6.0 or i["id"] in kev]
    epss = fetch_epss(i["id"] for i in candidates)

    by_segment = {}
    for seg_id, seg in SEGMENTS.items():
        by_segment[seg_id] = {
            "label": seg["label"],
            "blurb": seg["blurb"],
            "items": [],
        }

    for item in items:
        hits = match_segments(item)
        if not hits:
            continue
        e = epss.get(item["id"], 0.0)
        kev_entry = kev.get(item["id"])
        for seg_id in hits:
            total, factors = score(item, kev_entry, e, in_segment=True)
            if total < 25:
                continue
            by_segment[seg_id]["items"].append({
                "id": item["id"],
                "headline": headline(item),
                "products": vendors(item),
                "score": total,
                "factors": factors,
                "kev": bool(kev_entry),
                "ransomware": bool(kev_entry and kev_entry.get("ransomware")),
                "epss": round(e, 3),
                "cvss": item["cvss"],
                "url": item["url"],
                "take": takes.get(item["id"], ""),
                "action": kev_entry.get("action", "") if kev_entry else "",
            })

    for seg in by_segment.values():
        seg["items"].sort(key=lambda x: (-x["score"], x["id"]))
        seg["items"] = seg["items"][:ITEMS_PER_SEGMENT]
        seg["above"] = sum(1 for i in seg["items"] if i["score"] >= CUTLINE)

    payload = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window_hours": LOOKBACK_HOURS,
        "scanned": scanned,
        "cutline": CUTLINE,
        "segments": by_segment,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print(f"Wrote {OUT} -- {scanned} scanned, "
          f"{sum(len(s['items']) for s in by_segment.values())} matched across "
          f"{len(by_segment)} segments.")


if __name__ == "__main__":
    sys.exit(main())
