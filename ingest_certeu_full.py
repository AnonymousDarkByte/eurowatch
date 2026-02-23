"""
Full CERT-EU archive ingestion using the JSON endpoint.
Covers 2020-present, ~500+ advisories.
"""
import time
import httpx
import re
from datetime import datetime
from sqlmodel import Session, select
from database import engine, create_db
from models import Incident
from classifier import classify_severity, classify_sector, classify_attack_type

BASE = "https://cert.europa.eu"
YEARS = list(range(2020, 2027))


def get_advisory_links(year: int) -> list[str]:
    url = f"{BASE}/publications/security-advisories/{year}"
    with httpx.Client(timeout=15) as client:
        r = client.get(url)
        r.raise_for_status()
        links = re.findall(
            r'href="(/publications/security-advisories/\d{4}-\d+/?)"',
            r.text
        )
        return list(dict.fromkeys(links))  # deduplicate, preserve order


def fetch_advisory_json(path: str) -> dict | None:
    url = f"{BASE}{path.rstrip('/')}/json"
    for attempt in range(3):
        with httpx.Client(timeout=20, follow_redirects=True) as client:
            try:
                r = client.get(url)
                r.raise_for_status()
                return r.json()
            except Exception:
                if attempt < 2:
                    time.sleep(3)
                return None


def parse_date(date_str: str | None) -> datetime:
    if not date_str:
        return datetime.now()
    for fmt in ["%d-%m-%Y %H:%M:%S", "%d-%m-%Y", "%Y-%m-%d"]:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    return datetime.now()


def extract_cves(text: str) -> str | None:
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text)
    return ",".join(sorted(set(cves))) if cves else None


def already_exists(session: Session, source_url: str) -> bool:
    return session.exec(
        select(Incident).where(Incident.source_url == source_url)
    ).first() is not None


def run(years: list[int] | None = None):
    create_db()
    target_years = years or YEARS
    print(f"Years to process: {target_years}")

    new_count = 0
    skip_count = 0
    fail_count = 0

    with Session(engine) as session:
        for year in target_years:
            links = get_advisory_links(year)
            print(f"\n{year}: {len(links)} advisories found")

            for path in links:
                source_url = f"{BASE}{path}"

                if already_exists(session, source_url):
                    skip_count += 1
                    continue

                data = fetch_advisory_json(path)
                if not data:
                    fail_count += 1
                    continue

                title = data.get("title", "").strip()
                description = re.sub(r"<[^>]+>", " ", data.get("description", ""))
                description = re.sub(r"\s+", " ", description).strip()
                date_str = data.get("publish_date")
                serial = data.get("serial_number", "")

                full_text = f"{title} {description}"

                incident = Incident(
                    source="CERT_EU",
                    source_url=source_url,
                    date_published=parse_date(date_str),
                    title=f"{serial}: {title}" if serial else title,
                    raw_text=description[:1000],
                    severity=classify_severity(full_text),
                    sector=classify_sector(full_text),
                    attack_type=classify_attack_type(full_text),
                    cve_ids=extract_cves(full_text),
                    countries=None,  # CERT-EU advisories are EU-wide
                )

                session.add(incident)
                new_count += 1
                print(f"  + {serial}: {title[:60]}")
                time.sleep(0.5)  # be polite to CERT-EU servers

        session.commit()

    print(f"\nDone. Added: {new_count}. Skipped: {skip_count}. Failed: {fail_count}.")


if __name__ == "__main__":
    run()