"""MITRE ATT&CK service — fetch, sync, and map techniques to intel items."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)

# MITRE ATT&CK Enterprise STIX bundle (JSON)
ATTACK_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

# ─── 14 ATT&CK Tactics in kill-chain order ───────────────
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_LABELS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


# ─── Fetch & Parse ────────────────────────────────────────
async def fetch_attack_data() -> list[dict]:
    """Fetch the MITRE ATT&CK Enterprise STIX bundle and extract techniques."""
    logger.info("mitre_fetch_start")
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(ATTACK_ENTERPRISE_URL)
        resp.raise_for_status()
        bundle = resp.json()

    objects = bundle.get("objects", [])
    techniques: list[dict] = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Extract technique ID from external_references
        ext_refs = obj.get("external_references", [])
        technique_id = None
        url = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break

        if not technique_id:
            continue

        # Extract tactic(s) from kill_chain_phases
        kill_chain = obj.get("kill_chain_phases", [])
        tactics = [
            p["phase_name"]
            for p in kill_chain
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        # Extract platforms, data sources
        platforms = obj.get("x_mitre_platforms", [])
        detection = obj.get("x_mitre_detection", "")
        data_sources = obj.get("x_mitre_data_sources", [])

        is_sub = obj.get("x_mitre_is_subtechnique", False)
        parent_id = technique_id.split(".")[0] if is_sub else None

        name = obj.get("name", "")
        description = obj.get("description", "")

        # A technique can appear in multiple tactics
        for tactic in (tactics or ["unknown"]):
            techniques.append({
                "id": technique_id,
                "name": name,
                "tactic": tactic,
                "tactic_label": TACTIC_LABELS.get(tactic, tactic.replace("-", " ").title()),
                "description": description[:2000] if description else None,
                "url": url,
                "platforms": platforms,
                "detection": detection[:2000] if detection else None,
                "is_subtechnique": is_sub,
                "parent_id": parent_id,
                "data_sources": data_sources,
            })

    logger.info("mitre_fetch_complete", count=len(techniques))
    return techniques


# ─── Keyword-based ATT&CK Mapping ────────────────────────
# Maps keywords found in intel item text → ATT&CK technique IDs
# This provides a fast heuristic mapping; can be extended with ML later.
KEYWORD_TECHNIQUE_MAP: dict[str, list[str]] = {
    # Execution
    "powershell": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "command line": ["T1059"],
    "wscript": ["T1059.005"],
    "cscript": ["T1059.005"],
    "python script": ["T1059.006"],
    "bash": ["T1059.004"],
    "macro": ["T1204.002"],
    "shellcode": ["T1059"],

    # Persistence
    "registry run key": ["T1547.001"],
    "scheduled task": ["T1053.005"],
    "cron job": ["T1053.003"],
    "startup folder": ["T1547.001"],
    "boot or logon": ["T1547"],
    "web shell": ["T1505.003"],
    "implant": ["T1505"],

    # Privilege Escalation
    "privilege escalation": ["T1068"],
    "token manipulation": ["T1134"],
    "uac bypass": ["T1548.002"],
    "sudo": ["T1548.003"],

    # Defense Evasion
    "obfuscation": ["T1027"],
    "packing": ["T1027.002"],
    "code signing": ["T1553.002"],
    "masquerading": ["T1036"],
    "process injection": ["T1055"],
    "dll injection": ["T1055.001"],
    "reflective loading": ["T1620"],
    "rootkit": ["T1014"],

    # Credential Access
    "credential dump": ["T1003"],
    "mimikatz": ["T1003.001"],
    "lsass": ["T1003.001"],
    "brute force": ["T1110"],
    "password spray": ["T1110.003"],
    "credential stuffing": ["T1110.004"],
    "keylogger": ["T1056.001"],
    "phishing": ["T1566"],
    "spearphishing": ["T1566.001"],

    # Discovery
    "network scan": ["T1046"],
    "port scan": ["T1046"],
    "reconnaissance": ["T1595"],
    "active scanning": ["T1595"],

    # Lateral Movement
    "lateral movement": ["T1021"],
    "remote desktop": ["T1021.001"],
    "rdp": ["T1021.001"],
    "smb": ["T1021.002"],
    "psexec": ["T1569.002"],
    "wmi": ["T1047"],
    "pass the hash": ["T1550.002"],

    # Collection
    "screen capture": ["T1113"],
    "clipboard": ["T1115"],
    "keylogging": ["T1056.001"],

    # C2
    "command and control": ["T1071"],
    "c2 server": ["T1071"],
    "c2 beacon": ["T1071"],
    "dns tunneling": ["T1071.004"],
    "http c2": ["T1071.001"],
    "cobalt strike": ["T1071.001"],
    "reverse shell": ["T1059"],

    # Exfiltration
    "exfiltration": ["T1041"],
    "data exfil": ["T1041"],
    "data theft": ["T1041"],

    # Impact
    "ransomware": ["T1486"],
    "encryption": ["T1486"],
    "wiper": ["T1485"],
    "data destruction": ["T1485"],
    "defacement": ["T1491"],
    "denial of service": ["T1498"],
    "ddos": ["T1498"],
    "resource hijacking": ["T1496"],
    "cryptominer": ["T1496"],
    "cryptojacking": ["T1496"],

    # Initial Access
    "supply chain": ["T1195"],
    "drive-by": ["T1189"],
    "watering hole": ["T1189"],
    "exploit public": ["T1190"],
    "external remote": ["T1133"],
    "vpn exploit": ["T1133"],
    "trusted relationship": ["T1199"],
}

# Compile regex patterns once
_COMPILED_PATTERNS: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE), tech_ids)
    for kw, tech_ids in KEYWORD_TECHNIQUE_MAP.items()
]


def map_text_to_techniques(text: str) -> list[str]:
    """Return a deduplicated list of ATT&CK technique IDs found in text."""
    if not text:
        return []

    matched: set[str] = set()
    for pattern, tech_ids in _COMPILED_PATTERNS:
        if pattern.search(text):
            matched.update(tech_ids)

    return sorted(matched)


def map_intel_item_to_techniques(item: dict) -> list[str]:
    """Map an intel item dict to ATT&CK techniques based on its text fields."""
    parts = [
        item.get("title", ""),
        item.get("summary", "") or "",
        item.get("description", "") or "",
        " ".join(item.get("tags", [])),
    ]
    combined = " ".join(parts)
    return map_text_to_techniques(combined)
