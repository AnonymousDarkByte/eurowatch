# 👁 EuroWatch

**EU Critical Infrastructure Cyber Incident Transparency Monitor**

EuroWatch aggregates, normalizes, and visualizes publicly reported cyberattacks and vulnerabilities targeting European critical infrastructure — making scattered, multi-language, multi-agency data accessible in one place.

## What it does

- Ingests advisories from CERT-EU, the ENISA EU CSIRTs Network (27 EU member states), and more
- Normalizes everything into a consistent schema: sector, severity, affected countries, CVE IDs
- Serves a filterable REST API and public dashboard
- Runs ingestion automatically every 4 hours

## Live data sources

| Source | Type | Coverage |
|--------|------|----------|
| [CERT-EU](https://cert.europa.eu) | RSS feed | EU institutional advisories |
| [ENISA CSIRTs Network](https://github.com/enisaeu/CNW) | GitHub repo | All 27 EU member state CERTs |

## Running locally
```bash
# Clone and set up
git clone https://github.com/AnonymousDarkByte/eurowatch
cd eurowatch
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn sqlmodel httpx feedparser apscheduler aiofiles

# Run ingestion
python3 ingest_certeu.py
python3 ingest_cnw.py

# Start API server
uvicorn main:app --reload
```

Then open:
- Dashboard: http://127.0.0.1:8000/ui
- API docs: http://127.0.0.1:8000/docs
- Stats: http://127.0.0.1:8000/stats

## API
```
GET /incidents              # All incidents
GET /incidents?severity=critical&country=DE  # Filtered
GET /incidents?sector=energy
GET /stats                  # Aggregated counts
POST /ingest                # Trigger manual ingestion
```

## Data schema

Each incident record contains: `id`, `source`, `source_url`, `date_published`, `title`, `severity`, `sector`, `attack_type`, `cve_ids`, `countries`, `raw_text`

## Regulatory context

This project supports transparency goals of the EU NIS2 Directive and the EU Cyber Resilience Act (CRA) by making public incident data more accessible to citizens, researchers, and policymakers.

## License

Apache 2.0 — free to use, modify, and distribute.

## Status

Active development. Currently tracking ~40 incidents from 2 sources (2024–2026). Backfill to 2021 and additional sources in progress.
