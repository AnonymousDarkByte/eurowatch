import httpx
import re
from datetime import datetime
from sqlmodel import Session, select
from database import engine, create_db
from models import Incident

GITHUB_API = "https://api.github.com/repos/enisaeu/CNW/contents/advisories"
RAW_BASE = "https://raw.githubusercontent.com/enisaeu/CNW/main/advisories"

# Map markdown table country codes to ISO 3166-1 alpha-2
# EUI = EU institution (CERT-EU), not a country code
KNOWN_COUNTRIES = {
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
    "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT",
    "NL", "PL", "PT", "RO", "SE", "SI", "SK"
}


def get_advisory_years() -> list[str]:
    """Get list of year folders in the advisories directory."""
    with httpx.Client(timeout=15) as client:
        r = client.get(GITHUB_API)
        r.raise_for_status()
        return [item["name"] for item in r.json() if item["type"] == "dir"]


def get_advisory_files(year: str) -> list[dict]:
    """Get list of advisory files for a given year."""
    with httpx.Client(timeout=15) as client:
        r = client.get(f"{GITHUB_API}/{year}")
        r.raise_for_status()
        return [item for item in r.json() if item["name"].endswith(".md")]


def fetch_markdown(year: str, filename: str) -> str:
    """Fetch the raw markdown content of an advisory."""
    url = f"{RAW_BASE}/{year}/{filename}"
    with httpx.Client(timeout=15) as client:
        r = client.get(url)
        r.raise_for_status()
        return r.text


def parse_table_field(markdown: str, field: str) -> str | None:
    """Extract a value from the markdown metadata table by field name."""
    pattern = rf"\|\s*\*\*{field}\*\*\s*\|\s*(.+?)\s*\|"
    match = re.search(pattern, markdown, re.IGNORECASE)
    if match:
        # Strip markdown links, leaving just text
        text = match.group(1)
        text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
        return text.strip()
    return None


def parse_date(date_str: str | None) -> datetime:
    """Parse date strings like '09-01-2025' or '09-01-2025 (updated 13-01-2025)'."""
    if not date_str:
        return datetime.now()
    # Take only the first date if there's an 'updated' note
    match = re.search(r"(\d{2}-\d{2}-\d{4})", date_str)
    if match:
        try:
            return datetime.strptime(match.group(1), "%d-%m-%Y")
        except ValueError:
            pass
    return datetime.now()


def extract_cves(markdown: str) -> str | None:
    """Extract all CVE IDs mentioned anywhere in the document."""
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", markdown)
    return ",".join(sorted(set(cves))) if cves else None


def extract_countries(markdown: str) -> str | None:
    """
    Extract country codes from the 'List of CSIRTs Network member alerts' table.
    A country is included if it has a specific linked advisory (not just a generic page).
    """
    countries = set()
    # Find rows in the member table that have a bolded (specific) advisory link
    # Bold links look like: [**Title**](url)
    lines = markdown.split("\n")
    in_member_table = False

    for line in lines:
        if "List of CSIRTs Network member alerts" in line:
            in_member_table = True
            continue

        if in_member_table and line.startswith("|"):
            # Extract country code — first cell of table row
            cells = [c.strip() for c in line.split("|") if c.strip()]
            if not cells:
                continue
            country = cells[0].strip().upper()
            if country in KNOWN_COUNTRIES:
                # Only count if they issued a specific advisory (bolded link)
                if "**" in line:
                    countries.add(country)

    return ",".join(sorted(countries)) if countries else None


from classifier import classify_severity, classify_sector, classify_attack_type

def already_exists(session: Session, source_url: str) -> bool:
    return session.exec(
        select(Incident).where(Incident.source_url == source_url)
    ).first() is not None


def run(years: list[str] | None = None):
    """
    Run ingestion. Pass a list of years to limit scope,
    e.g. years=["2025"] for recent only.
    Defaults to all available years.
    """
    create_db()

    available_years = get_advisory_years()
    target_years = years if years else available_years
    print(f"Years to process: {target_years}")

    new_count = 0
    skip_count = 0

    with Session(engine) as session:
        for year in target_years:
            files = get_advisory_files(year)
            print(f"\n{year}: {len(files)} advisories found")

            for file in files:
                filename = file["name"]
                # advisory ID is the filename without .md
                advisory_id = filename.replace(".md", "")
                source_url = f"https://github.com/enisaeu/CNW/blob/main/advisories/{year}/{filename}"

                if already_exists(session, source_url):
                    skip_count += 1
                    continue

                try:
                    markdown = fetch_markdown(year, filename)
                except Exception as e:
                    print(f"  Failed to fetch {filename}: {e}")
                    skip_count += 1
                    continue

                # Parse title from first heading
                title_match = re.search(r"^#\s+(.+)$", markdown, re.MULTILINE)
                title = title_match.group(1).strip() if title_match else advisory_id

                date_str = parse_table_field(markdown, "Date")
                details = parse_table_field(markdown, "Details") or ""
                keywords = parse_table_field(markdown, "Keywords") or ""

                full_text = title + " " + keywords + " " + details
                countries = extract_countries(markdown)

                incident = Incident(
                    source="ENISA_CNW",
                    source_url=source_url,
                    date_published=parse_date(date_str),
                    title=title,
                    raw_text=details,
                    severity=classify_severity(full_text),
                    sector=classify_sector(full_text),
                    attack_type=classify_attack_type(full_text),
                    cve_ids=extract_cves(markdown),
                    countries=countries,
                )

                session.add(incident)
                new_count += 1
                country_count = len(countries.split(",")) if countries else 0
                print(f"  + [{country_count} countries] {title[:65]}")

        session.commit()

    print(f"\nDone. Added: {new_count} new. Skipped: {skip_count}.")


if __name__ == "__main__":
    # Start with 2024 and 2025 only — add earlier years later for backfill
    run(years=["2024", "2025"])