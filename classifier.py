"""
Shared classification logic used by all ingestion pipelines.
Import from here instead of duplicating in each ingest file.
"""


SEVERITY_KEYWORDS = {
    "critical": [
        "critical", "zero-day", "0-day", "actively exploited",
        "exploitation detected", "exploitation observed", "in the wild",
        "unauthenticated remote code execution", "cvss 9", "cvss 10",
        "emergency", "urgent patch"
    ],
    "high": [
        "high", "remote code execution", "rce", "unauthenticated",
        "privilege escalation", "authentication bypass", "severe",
        "cvss 7", "cvss 8", "arbitrary code"
    ],
    "medium": [
        "medium", "moderate", "cross-site scripting", "xss",
        "sql injection", "information disclosure", "cvss 4", "cvss 5", "cvss 6"
    ],
    "low": [
        "low severity", "minor", "informational", "cvss 1", "cvss 2", "cvss 3"
    ]
}

SECTOR_KEYWORDS = {
    "energy": [
        "energy", "power grid", "power plant", "electrical grid",
        "scada", "ics", "industrial control", "ot security",
        "operational technology", "substation", "smart grid",
        "siemens energy", "schneider electric", "abb", "ge energy",
        "oil", "gas pipeline", "nuclear"
    ],
    "water": [
        "water", "wastewater", "water treatment", "water utility",
        "sewage", "water supply", "water infrastructure"
    ],
    "telecom": [
        "telecom", "5g", "router", "cisco", "juniper", "fortinet",
        "fortigate", "fortimanager", "fortiproxy", "fortios",
        "palo alto", "pan-os", "checkpoint", "sonicwall",
        "network device", "vpn", "ssl vpn", "firewall",
        "ivanti connect", "pulse secure", "citrix netscaler",
        "f5 big-ip", "big-ip", "load balancer", "network infrastructure",
        "bgp", "dns", "carrier", "isp"
    ],
    "health": [
        "hospital", "health", "medical", "patient", "clinical",
        "healthcare", "nhs", "ehr", "electronic health",
        "medical device", "radiology", "pharmacy"
    ],
    "finance": [
        "bank", "finance", "financial", "payment", "swift",
        "trading", "stock exchange", "insurance", "fintech"
    ],
    "transport": [
        "transport", "aviation", "airport", "rail", "railway",
        "maritime", "shipping", "logistics", "traffic management"
    ],
    "government": [
        "government", "public administration", "ministry",
        "parliament", "municipality", "public sector", "nato",
        "defence", "military", "law enforcement", "police"
    ],
    "general-it": [
        "windows", "microsoft", "active directory", "exchange",
        "sharepoint", "vmware", "vsphere", "esxi",
        "connectwise", "teamcity", "openmetadata", "moveit",
        "solarwinds", "veeam", "crowdstrike", "openssh",
        "linux", "android", "apple", "chrome", "firefox",
        "ivanti", "cups", "xz utils", "log4j", "spring",
        "react", "node.js", "apache", "nginx", "jenkins",
        "gitlab", "github actions", "docker", "kubernetes"
    ]
}

ATTACK_TYPE_KEYWORDS = {
    "ransomware": ["ransomware", "ransom", "encrypted files", "lockbit", "blackcat", "cl0p"],
    "ddos": ["ddos", "denial of service", "dos attack", "volumetric"],
    "apt": ["apt", "state-sponsored", "nation-state", "advanced persistent",
            "lazarus", "fancy bear", "cozy bear", "sandworm", "volt typhoon"],
    "supply-chain": ["supply chain", "supply-chain", "third-party", "software update",
                     "build system", "dependency", "open source package"],
    "phishing": ["phishing", "spear-phishing", "spearphishing", "social engineering"],
    "data-breach": ["data breach", "data leak", "exfiltration", "stolen data",
                    "sensitive data", "personal data exposed"],
    "ics-exploit": ["ics exploit", "scada exploit", "plc", "hmi exploit",
                    "modbus", "dnp3", "iec 61850"]
}


def classify_severity(text: str) -> str | None:
    text = text.lower()
    for level, keywords in SEVERITY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return level
    return None


def classify_sector(text: str) -> str | None:
    text = text.lower()
    # Check specific sectors first, general-it last
    priority = ["energy", "water", "telecom", "health", "finance", "transport", "government", "general-it"]
    for sector in priority:
        if any(kw in text for kw in SECTOR_KEYWORDS[sector]):
            return sector
    return None


def classify_attack_type(text: str) -> str | None:
    text = text.lower()
    for attack_type, keywords in ATTACK_TYPE_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return attack_type
    return None