import feedparser
from datetime import datetime
from email.utils import parsedate_to_datetime
from sqlmodel import Session, select
from database import engine, create_db
from models import Incident

CERT_EU_RSS = "https://www.cert.europa.eu/publications/security-advisories-rss"


def parse_date(entry) -> datetime | None:
    """Try every date field feedparser might populate."""
    for field in ["published", "updated"]:
        raw = entry.get(field)
        if raw:
            try:
                return parsedate_to_datetime(raw).replace(tzinfo=None)
            except Exception:
                pass
    if entry.get("published_parsed"):
        t = entry.published_parsed
        return datetime(*t[:6])
    return datetime.utcnow()


def classify_severity(title: str, summary: str) -> str | None:
    """Simple keyword-based severity classification."""
    text = (title + " " + summary).lower()
    if any(w in text for w in ["critical", "actively exploited", "zero-day", "0-day"]):
        return "critical"
    if any(w in text for w in ["high", "severe", "remote code execution", "rce"]):
        return "high"
    if any(w in text for w in ["medium", "moderate", "privilege escalation"]):
        return "medium"
    if any(w in text for w in ["low", "minor", "informational"]):
        return "low"
    return None


def classify_sector(title: str, summary: str) -> str | None:
    """Simple keyword-based sector classification."""
    text = (title + " " + summary).lower()
    if any(w in text for w in ["energy", "power", "grid", "scada", "ics", "industrial"]):
        return "energy"
    if any(w in text for w in ["water", "wastewater", "treatment plant"]):
        return "water"
    if any(w in text for w in ["telecom", "5g", "network", "router", "cisco", "juniper"]):
        return "telecom"
    if any(w in text for w in ["hospital", "health", "medical", "patient"]):
        return "health"
    if any(w in text for w in ["bank", "finance", "financial", "payment"]):
        return "finance"
    if any(w in text for w in ["transport", "aviation", "rail", "maritime"]):
        return "transport"
    return None


def classify_attack_type(title: str, summary: str) -> str | None:
    """Simple keyword-based attack type classification."""
    text = (title + " " + summary).lower()
    if any(w in text for w in ["ransomware"]):
        return "ransomware"
    if any(w in text for w in ["ddos", "denial of service"]):
        return "ddos"
    if any(w in text for w in ["apt", "state-sponsored", "nation-state"]):
        return "apt"
    if any(w in text for w in ["supply chain", "supply-chain", "third-party"]):
        return "supply-chain"
    if any(w in text for w in ["phishing", "spear-phishing"]):
        return "phishing"
    if any(w in text for w in ["data breach", "data leak", "exfiltration"]):
        return "data-breach"
    return None


def extract_cves(text: str) -> str | None:
    """Pull out any CVE IDs mentioned in the text."""
    import re
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text)
    return ",".join(sorted(set(cves))) if cves else None


def already_exists(session: Session, source_url: str) -> bool:
    result = session.exec(
        select(Incident).where(Incident.source_url == source_url)
    ).first()
    return result is not None


def run():
    create_db()
    print(f"Fetching CERT-EU RSS feed...")

    feed = feedparser.parse(CERT_EU_RSS)

    if feed.bozo:
        print(f"Warning: feed parsing issue: {feed.bozo_exception}")

    print(f"Found {len(feed.entries)} entries in feed.")

    new_count = 0
    skip_count = 0

    with Session(engine) as session:
        for entry in feed.entries:
            url = entry.get("link", "")
            if not url:
                skip_count += 1
                continue

            if already_exists(session, url):
                skip_count += 1
                continue

            title = entry.get("title", "No title")
            summary = entry.get("summary", "") or ""
            full_text = title + " " + summary

            incident = Incident(
                source="CERT_EU",
                source_url=url,
                date_published=parse_date(entry),
                title=title,
                raw_text=summary,
                severity=classify_severity(title, summary),
                sector=classify_sector(title, summary),
                attack_type=classify_attack_type(title, summary),
                cve_ids=extract_cves(full_text),
                countries=None,  # CERT-EU advisories rarely specify a single country
            )

            session.add(incident)
            new_count += 1
            print(f"  + {title[:80]}")

        session.commit()

    print(f"\nDone. Added: {new_count} new records. Skipped: {skip_count}.")


if __name__ == "__main__":
    run()