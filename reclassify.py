"""
Run this once to reclassify all existing incidents with the improved classifier.
Safe to run multiple times — only updates records where classification is missing.
"""
from sqlmodel import Session, select
from database import engine
from models import Incident
from classifier import classify_severity, classify_sector, classify_attack_type


def run():
    with Session(engine) as session:
        incidents = session.exec(select(Incident)).all()
        updated = 0

        for incident in incidents:
            # Build full text from all available fields
            text = " ".join(filter(None, [
                incident.title,
                incident.raw_text,
                incident.cve_ids,
            ]))

            new_severity = classify_severity(text)
            new_sector = classify_sector(text)
            new_attack_type = classify_attack_type(text)

            changed = False
            if not incident.severity and new_severity:
                incident.severity = new_severity
                changed = True
            if not incident.sector and new_sector:
                incident.sector = new_sector
                changed = True
            if not incident.attack_type and new_attack_type:
                incident.attack_type = new_attack_type
                changed = True

            if changed:
                session.add(incident)
                updated += 1
                print(f"  Updated: {incident.title[:65]}")
                print(f"    sector={incident.sector} severity={incident.severity} attack={incident.attack_type}")

        session.commit()
        print(f"\nDone. Updated {updated} of {len(incidents)} records.")


if __name__ == "__main__":
    run()