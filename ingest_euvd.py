import httpx
from datetime import datetime
from sqlmodel import Session, select
from database import engine, create_db
from models import Incident

EUVD_API = "https://euvdservices.enisa.europa.eu/api"


def fetch_recent_vulnerabilities(size: int = 100) -> list[dict]:
    """Fetch the most recent vulnerabilities from ENISA EUVD."""
    url = f"{EUVD_API}/lastvulnerabilities"
    params = {"size": size}

    print(f"Fetching {size} vulnerabilities from ENISA EUVD...")

    with httpx.Client(timeout=30) as client:
        response = client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

    print(f"Got {len(data)} records from API.")
    return data


def parse_severity(cvss_score: float | None) -> str | None:
    """Convert a CVSS numeric score to a human-readable severity label."""
    if cvss_score is None:
        return None
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    else:
        return "low"


def normalize(raw: dict) -> Incident | None:
    """Map a raw EUVD API record to our Incident schema."""
    try:
        # Extract CVE IDs if present
        aliases = raw.get("aliases", []) or []
        cve_ids = ",".join(
            a.get("alias", "") for a in aliases
            if a.get("alias", "").startswith("CVE-")
        ) or None

        # Parse the published date
        date_str = raw.get("datePublished") or raw.get("dateUpdated")
        if not date_str:
            return None
        date_published = datetime.fromisoformat(date_str.replace("Z", "+00:00"))

        # Get CVSS score — try v3.1 first, fall back to v3 or v2
        cvss_score = (
            raw.get("baseScoreV31")
            or raw.get("baseScoreV3")
            or raw.get("baseScoreV2")
        )

        return Incident(
            source="ENISA_EUVD",
            source_url=f"https://euvd.enisa.europa.eu/enisa/{raw.get('id', '')}",
            date_published=date_published,
            title=raw.get("id", "Unknown") + " — " + (raw.get("description", "No description")[:120]),
            raw_text=raw.get("description"),
            severity=parse_severity(float(cvss_score) if cvss_score else None),
            cve_ids=cve_ids,
            # Sector and attack_type require more analysis — we add that in Phase 1
            sector=None,
            attack_type=None,
            countries=None,
        )
    except Exception as e:
        print(f"  Skipping record {raw.get('id', '?')}: {e}")
        return None


def already_exists(session: Session, source_url: str) -> bool:
    """Check if we already have this incident to avoid duplicates."""
    result = session.exec(
        select(Incident).where(Incident.source_url == source_url)
    ).first()
    return result is not None


def run():
    create_db()
    raw_records = fetch_recent_vulnerabilities(size=100)

    new_count = 0
    skip_count = 0