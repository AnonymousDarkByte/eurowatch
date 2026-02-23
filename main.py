from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi import FastAPI, Query
from sqlmodel import Session, select
from database import create_db, engine
from models import Incident
from typing import Optional
from apscheduler.schedulers.background import BackgroundScheduler
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("eurowatch")

app = FastAPI(
    title="EuroWatch API",
    description="EU Critical Infrastructure Cyber Incident Monitor",
    version="0.1.0"
)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/ui")
def ui():
    return FileResponse("static/index.html")

scheduler = BackgroundScheduler()


def run_all_ingestion():
    """Run all ingestion pipelines. Called by scheduler and on startup."""
    logger.info("Starting scheduled ingestion run...")
    try:
        from ingest_certeu import run as run_certeu
        run_certeu()
    except Exception as e:
        logger.error(f"CERT-EU ingestion failed: {e}")

    try:
        from ingest_cnw import run as run_cnw
        run_cnw(years=["2025", "2024"])
    except Exception as e:
        logger.error(f"CNW ingestion failed: {e}")

    logger.info("Ingestion run complete.")


@app.on_event("startup")
def on_startup():
    create_db()
    logger.info("Database ready.")

    # Schedule ingestion every 4 hours
    scheduler.add_job(run_all_ingestion, "interval", hours=4, id="ingestion")
    scheduler.start()
    logger.info("Scheduler started — ingestion runs every 4 hours.")


@app.on_event("shutdown")
def on_shutdown():
    scheduler.shutdown()
    logger.info("Scheduler stopped.")


@app.get("/")
def root():
    job = scheduler.get_job("ingestion")
    return {
        "project": "EuroWatch",
        "status": "running",
        "version": "0.1.0",
        "next_ingestion": str(job.next_run_time) if job else "unknown",
    }


@app.post("/ingest")
def trigger_ingestion():
    """Manually trigger ingestion without waiting for the schedule."""
    try:
        run_all_ingestion()
        return {"status": "ok", "message": "Ingestion completed."}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/incidents")
def get_incidents(
    source: Optional[str] = Query(None, description="CERT_EU / ENISA_CNW"),
    severity: Optional[str] = Query(None, description="critical / high / medium / low"),
    sector: Optional[str] = Query(None, description="energy / water / telecom / health"),
    country: Optional[str] = Query(None, description="ISO code e.g. DE, FR, NL"),
    limit: int = Query(50, le=200),
):
    with Session(engine) as session:
        incidents = session.exec(
            select(Incident).order_by(Incident.date_published.desc())
        ).all()

        if source:
            incidents = [i for i in incidents if i.source == source.upper()]
        if severity:
            incidents = [i for i in incidents if i.severity == severity.lower()]
        if sector:
            incidents = [i for i in incidents if i.sector == sector.lower()]
        if country:
            incidents = [
                i for i in incidents
                if i.countries and country.upper() in i.countries.split(",")
            ]

        incidents = incidents[:limit]

        return {
            "total": len(incidents),
            "filters": {
                "source": source,
                "severity": severity,
                "sector": sector,
                "country": country,
            },
            "incidents": [
                {
                    "id": i.id,
                    "title": i.title,
                    "source": i.source,
                    "source_url": i.source_url,
                    "date_published": i.date_published.isoformat(),
                    "severity": i.severity,
                    "sector": i.sector,
                    "attack_type": i.attack_type,
                    "cve_ids": i.cve_ids,
                    "countries": i.countries.split(",") if i.countries else [],
                }
                for i in incidents
            ]
        }


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    with Session(engine) as session:
        incident = session.get(Incident, incident_id)
        if not incident:
            return {"error": f"Incident {incident_id} not found"}
        return incident


@app.get("/stats")
def get_stats():
    with Session(engine) as session:
        all_incidents = session.exec(select(Incident)).all()

        severity_counts = {}
        sector_counts = {}
        source_counts = {}
        country_counts = {}

        for i in all_incidents:
            s = i.severity or "unknown"
            severity_counts[s] = severity_counts.get(s, 0) + 1

            sec = i.sector or "unclassified"
            sector_counts[sec] = sector_counts.get(sec, 0) + 1

            src = i.source
            source_counts[src] = source_counts.get(src, 0) + 1

            if i.countries:
                for c in i.countries.split(","):
                    country_counts[c] = country_counts.get(c, 0) + 1

        # Sort country counts highest first
        country_counts = dict(
            sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        )

        return {
            "total_incidents": len(all_incidents),
            "by_severity": severity_counts,
            "by_sector": sector_counts,
            "by_source": source_counts,
            "by_country": country_counts,
        }