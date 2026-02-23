"""
Two-pass fix for unclassified records:
1. Re-run classifier on records that have raw_text but no sector
2. Fetch full text from source URL for records with no text, then classify
"""
import httpx
import re
import time
from sqlmodel import Session, select
from database import engine
from models import Incident
from classifier import classify_severity, classify_sector, classify_attack_type


def fetch_text_from_github(url: str) -> str | None:
    """Fetch full markdown text from a CNW GitHub advisory."""
    raw_url = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
    try:
        r = httpx.get(raw_url, timeout=10)
        r.raise_for_status()
        # Strip markdown formatting
        text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', r.text)
        text = re.sub(r'[#*|]', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text[:2000]
    except Exception:
        return None


def fetch_text_from_certeu(url: str) -> str | None:
    """Fetch description from CERT-EU JSON endpoint."""
    # Extract advisory ID from URL e.g. /2023-001/
    match = re.search(r'/security-advisories/(\d{4}-\d+)/?$', url)
    if not match:
        return None
    advisory_id = match.group(1)
    json_url = f"https://cert.europa.eu/publications/security-advisories/{advisory_id}/json"
    try:
        r = httpx.get(json_url, timeout=10, follow_redirects=True)
        r.raise_for_status()
        data = r.json()
        desc = data.get("description", "")
        desc = re.sub(r'<[^>]+>', ' ', desc)
        desc = re.sub(r'\s+', ' ', desc).strip()
        return desc[:2000]
    except Exception:
        return None


def run():
    with Session(engine) as session:
        unclassified = session.exec(
            select(Incident).where(Incident.sector == None)
        ).all()
        print(f"Found {len(unclassified)} unclassified records")

        updated = 0
        fetched = 0

        for i in unclassified:
            text = i.raw_text or ""

            # If no text, try to fetch it
            if not text:
                if "github.com" in i.source_url:
                    text = fetch_text_from_github(i.source_url) or ""
                    if text:
                        fetched += 1
                        i.raw_text = text[:1000]
                elif "cert.europa.eu" in i.source_url:
                    text = fetch_text_from_certeu(i.source_url) or ""
                    if text:
                        fetched += 1
                        i.raw_text = text[:1000]
                time.sleep(0.3)

            # Now classify using title + fetched text
            full_text = f"{i.title} {text}"
            new_sector = classify_sector(full_text)
            new_severity = classify_severity(full_text) if not i.severity else i.severity
            new_attack = classify_attack_type(full_text) if not i.attack_type else i.attack_type

            if new_sector:
                i.sector = new_sector
                i.severity = new_severity
                i.attack_type = new_attack
                session.add(i)
                updated += 1
                print(f"  ✓ {i.title[:60]}")
                print(f"    sector={new_sector} severity={new_severity}")

        session.commit()
        print(f"\nDone. Fetched text for {fetched} records. Classified {updated} of {len(unclassified)}.")


if __name__ == "__main__":
    run()