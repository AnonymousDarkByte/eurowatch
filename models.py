from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel
import uuid


class Incident(SQLModel, table=True):
    id: str = Field(
        default_factory=lambda: f"EW-{datetime.now().year}-{uuid.uuid4().hex[:8].upper()}",
        primary_key=True
    )
    source: str                          # e.g. "ENISA_EUVD", "CISA_ICS", "CERT_EU"
    source_url: str                      # original advisory URL
    date_published: datetime
    date_ingested: datetime = Field(default_factory=datetime.utcnow)
    title: str
    summary: Optional[str] = None        # plain language summary (we add this later)
    sector: Optional[str] = None         # energy / water / telecom / health / etc.
    countries: Optional[str] = None      # comma-separated ISO codes e.g. "DE,FR,NL"
    attack_type: Optional[str] = None    # ransomware / DDoS / APT / etc.
    severity: Optional[str] = None       # critical / high / medium / low
    cve_ids: Optional[str] = None        # comma-separated e.g. "CVE-2024-1234,CVE-2024-5678"
    raw_text: Optional[str] = None       # full original advisory text verbatim