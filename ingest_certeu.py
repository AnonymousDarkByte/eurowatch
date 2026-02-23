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


from classifier import classify_severity, classify_sector, classify_attack_type


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