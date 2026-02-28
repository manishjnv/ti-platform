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
# Expanded to cover CVE/vulnerability types, malware delivery, network
# attacks, and common tool names found across KEV, URLhaus, AbuseIPDB,
# NVD, and OTX feeds.
KEYWORD_TECHNIQUE_MAP: dict[str, list[str]] = {
    # ─── Initial Access ──────────────────────────────────
    "phishing": ["T1566"],
    "spearphishing": ["T1566.001"],
    "spear-phishing": ["T1566.001"],
    "phishing link": ["T1566.002"],
    "phishing attachment": ["T1566.001"],
    "malicious email": ["T1566"],
    "spam campaign": ["T1566"],
    "social engineering": ["T1566"],
    "drive-by": ["T1189"],
    "drive by compromise": ["T1189"],
    "drive by download": ["T1189"],
    "watering hole": ["T1189"],
    "supply chain": ["T1195"],
    "supply chain compromise": ["T1195"],
    "supply chain attack": ["T1195"],
    "software supply chain": ["T1195.002"],
    "trojanized": ["T1195.002"],
    "trojanised": ["T1195.002"],
    "backdoored package": ["T1195.002"],
    "exploit public": ["T1190"],
    "remote code execution": ["T1190", "T1203"],
    "rce vulnerability": ["T1190", "T1203"],
    "unauthenticated remote": ["T1190"],
    "external remote": ["T1133"],
    "vpn exploit": ["T1133"],
    "vpn vulnerability": ["T1133"],
    "trusted relationship": ["T1199"],
    "valid accounts": ["T1078"],
    "default credentials": ["T1078.001"],
    "hardcoded credentials": ["T1078.001"],
    "hard-coded credentials": ["T1078.001"],
    "default password": ["T1078.001"],
    "compromised credentials": ["T1078"],
    "stolen credentials": ["T1078"],
    "replication through removable": ["T1091"],
    "usb malware": ["T1091"],

    # ─── Execution ───────────────────────────────────────
    "powershell": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "command line": ["T1059"],
    "command injection": ["T1059"],
    "os command injection": ["T1059"],
    "command execution": ["T1059"],
    "arbitrary command": ["T1059"],
    "wscript": ["T1059.005"],
    "cscript": ["T1059.005"],
    "vbscript": ["T1059.005"],
    "javascript execution": ["T1059.007"],
    "python script": ["T1059.006"],
    "bash": ["T1059.004"],
    "shell command": ["T1059.004"],
    "macro": ["T1204.002"],
    "malicious macro": ["T1204.002"],
    "shellcode": ["T1059"],
    "code execution": ["T1203"],
    "arbitrary code execution": ["T1203"],
    "exploitation for client execution": ["T1203"],
    "user execution": ["T1204"],
    "malicious file": ["T1204.002"],
    "malicious link": ["T1204.001"],
    "malicious url": ["T1204.001"],
    "malicious document": ["T1204.002"],
    "windows management instrumentation": ["T1047"],
    "wmic": ["T1047"],
    "mshta": ["T1218.005"],
    "regsvr32": ["T1218.010"],
    "rundll32": ["T1218.011"],
    "certutil": ["T1218"],

    # ─── Persistence ─────────────────────────────────────
    "registry run key": ["T1547.001"],
    "run key": ["T1547.001"],
    "scheduled task": ["T1053.005"],
    "cron job": ["T1053.003"],
    "startup folder": ["T1547.001"],
    "boot or logon": ["T1547"],
    "autostart": ["T1547"],
    "web shell": ["T1505.003"],
    "webshell": ["T1505.003"],
    "implant": ["T1505"],
    "backdoor": ["T1505", "T1546"],
    "persistence mechanism": ["T1547"],
    "create account": ["T1136"],
    "account creation": ["T1136"],
    "dll side-loading": ["T1574.002"],
    "dll sideloading": ["T1574.002"],
    "dll hijacking": ["T1574.001"],
    "service installation": ["T1543.003"],
    "create service": ["T1543.003"],
    "modify registry": ["T1112"],
    "registry modification": ["T1112"],

    # ─── Privilege Escalation ────────────────────────────
    "privilege escalation": ["T1068"],
    "elevation of privilege": ["T1068"],
    "local privilege escalation": ["T1068"],
    "exploitation for privilege": ["T1068"],
    "token manipulation": ["T1134"],
    "access token": ["T1134"],
    "uac bypass": ["T1548.002"],
    "sudo": ["T1548.003"],
    "setuid": ["T1548.001"],
    "suid": ["T1548.001"],

    # ─── Defense Evasion ─────────────────────────────────
    "obfuscation": ["T1027"],
    "obfuscated files": ["T1027"],
    "packing": ["T1027.002"],
    "packed binary": ["T1027.002"],
    "code signing": ["T1553.002"],
    "invalid code signature": ["T1036.001"],
    "masquerading": ["T1036"],
    "process injection": ["T1055"],
    "dll injection": ["T1055.001"],
    "reflective loading": ["T1620"],
    "rootkit": ["T1014"],
    "disable antivirus": ["T1562.001"],
    "disable security": ["T1562.001"],
    "impair defenses": ["T1562"],
    "indicator removal": ["T1070"],
    "log deletion": ["T1070.001"],
    "clear logs": ["T1070.001"],
    "timestomping": ["T1070.006"],
    "protection mechanism failure": ["T1562"],
    "security control bypass": ["T1562"],
    "bypass authentication": ["T1562"],

    # ─── Credential Access ───────────────────────────────
    "credential dump": ["T1003"],
    "credential theft": ["T1003"],
    "credential harvesting": ["T1003"],
    "credential stealing": ["T1003"],
    "mimikatz": ["T1003.001"],
    "lsass": ["T1003.001"],
    "brute force": ["T1110"],
    "brute-force": ["T1110"],
    "password spray": ["T1110.003"],
    "credential stuffing": ["T1110.004"],
    "keylogger": ["T1056.001"],
    "input capture": ["T1056"],
    "unsalted hash": ["T1110.002"],
    "password hash": ["T1003"],
    "authentication bypass": ["T1556"],
    "improper authentication": ["T1556"],
    "multi-factor authentication": ["T1556.006"],

    # ─── Discovery ───────────────────────────────────────
    "network scan": ["T1046"],
    "port scan": ["T1046"],
    "network scanning": ["T1046"],
    "reconnaissance": ["T1595"],
    "active scanning": ["T1595"],
    "information gathering": ["T1592"],
    "system information discovery": ["T1082"],
    "network discovery": ["T1046"],
    "directory listing": ["T1083"],
    "directory traversal": ["T1083"],
    "path traversal": ["T1083"],
    "file and directory discovery": ["T1083"],
    "account discovery": ["T1087"],
    "permission groups": ["T1069"],

    # ─── Lateral Movement ────────────────────────────────
    "lateral movement": ["T1021"],
    "remote desktop": ["T1021.001"],
    "rdp": ["T1021.001"],
    "smb": ["T1021.002"],
    "psexec": ["T1569.002"],
    "wmi": ["T1047"],
    "pass the hash": ["T1550.002"],
    "pass the ticket": ["T1550.003"],
    "ssh": ["T1021.004"],
    "remote service": ["T1021"],

    # ─── Collection ──────────────────────────────────────
    "screen capture": ["T1113"],
    "clipboard": ["T1115"],
    "keylogging": ["T1056.001"],
    "data collection": ["T1119"],
    "data from local system": ["T1005"],
    "email collection": ["T1114"],
    "information disclosure": ["T1005"],
    "data leak": ["T1005"],

    # ─── Command and Control ─────────────────────────────
    "command and control": ["T1071"],
    "c2 server": ["T1071"],
    "c2 beacon": ["T1071"],
    "c2 channel": ["T1071"],
    "c2 communication": ["T1071"],
    "c2 infrastructure": ["T1071"],
    "dns tunneling": ["T1071.004"],
    "http c2": ["T1071.001"],
    "cobalt strike": ["T1071.001", "T1059.001"],
    "reverse shell": ["T1059"],
    "ingress tool transfer": ["T1105"],
    "remote access trojan": ["T1219"],
    "rat malware": ["T1219"],
    "remote access tool": ["T1219"],
    "proxy": ["T1090"],
    "encrypted channel": ["T1573"],
    "non-standard port": ["T1571"],

    # ─── Exfiltration ────────────────────────────────────
    "exfiltration": ["T1041"],
    "data exfil": ["T1041"],
    "data theft": ["T1041"],
    "data exfiltration": ["T1041"],
    "data breach": ["T1041"],
    "stolen data": ["T1041"],
    "sensitive data exposure": ["T1041"],

    # ─── Impact ──────────────────────────────────────────
    "ransomware": ["T1486"],
    "ransom demand": ["T1486"],
    "file encryption malware": ["T1486"],
    "encrypted for ransom": ["T1486"],
    "lockbit": ["T1486"],
    "conti ransomware": ["T1486"],
    "blackcat": ["T1486"],
    "alphv": ["T1486"],
    "play ransomware": ["T1486"],
    "clop": ["T1486"],
    "royal ransomware": ["T1486"],
    "akira ransomware": ["T1486"],
    "black basta": ["T1486"],
    "wiper": ["T1485"],
    "data destruction": ["T1485"],
    "disk wipe": ["T1485"],
    "defacement": ["T1491"],
    "denial of service": ["T1498"],
    "ddos": ["T1498"],
    "dos attack": ["T1498"],
    "resource hijacking": ["T1496"],
    "cryptominer": ["T1496"],
    "cryptojacking": ["T1496"],
    "coin miner": ["T1496"],

    # ─── Vulnerability Type → Technique Mappings ─────────
    # (critical for KEV, NVD, Shodan CVE data which makes up 40%+ of intel)
    "cross-site scripting": ["T1059.007"],
    "xss vulnerability": ["T1059.007"],
    "reflected xss": ["T1059.007"],
    "stored xss": ["T1059.007"],
    "sql injection": ["T1190"],
    "sqli": ["T1190"],
    "deserialization": ["T1190", "T1059"],
    "deserialization of untrusted": ["T1190"],
    "insecure deserialization": ["T1190"],
    "buffer overflow": ["T1190", "T1203"],
    "heap overflow": ["T1190", "T1203"],
    "stack overflow": ["T1190", "T1203"],
    "integer overflow": ["T1190", "T1203"],
    "memory corruption": ["T1190", "T1203"],
    "use-after-free": ["T1190", "T1203"],
    "use after free": ["T1190", "T1203"],
    "double free": ["T1190", "T1203"],
    "null pointer dereference": ["T1499.004"],
    "type confusion": ["T1190", "T1203"],
    "server-side request forgery": ["T1190"],
    "ssrf": ["T1190"],
    "xml external entity": ["T1190"],
    "xxe": ["T1190"],
    "local file inclusion": ["T1083", "T1005"],
    "remote file inclusion": ["T1190"],
    "code injection": ["T1190", "T1059"],
    "template injection": ["T1190", "T1059"],
    "ldap injection": ["T1190"],
    "arbitrary file upload": ["T1190", "T1505.003"],
    "unrestricted upload": ["T1190", "T1505.003"],
    "file upload vulnerability": ["T1190", "T1505.003"],
    "improper input validation": ["T1190"],
    "improper access control": ["T1068"],
    "improper authorization": ["T1068"],
    "missing authorization": ["T1068"],
    "broken access control": ["T1068"],
    "security misconfiguration": ["T1190"],
    "insecure configuration": ["T1190"],
    "information exposure": ["T1005"],
    "sensitive information": ["T1005"],
    "out-of-bounds write": ["T1190", "T1203"],
    "out-of-bounds read": ["T1005"],

    # ─── Malware Delivery & URLhaus Patterns ─────────────
    # (critical for URLhaus data which makes up 32% of intel)
    "malware distribution": ["T1105", "T1204"],
    "malware hosting": ["T1105", "T1204.001"],
    "malware download": ["T1105", "T1204"],
    "payload delivery": ["T1105", "T1204"],
    "dropper": ["T1105", "T1204.002"],
    "loader": ["T1105"],
    "downloader": ["T1105"],
    "emotet": ["T1566.001", "T1059.001", "T1055", "T1071.001"],
    "qakbot": ["T1566.001", "T1059.001", "T1055"],
    "qbot": ["T1566.001", "T1059.001", "T1055"],
    "trickbot": ["T1566.001", "T1059.001", "T1055"],
    "icedid": ["T1566.001", "T1059.001"],
    "gozi": ["T1566.001", "T1071.001"],
    "ursnif": ["T1566.001", "T1071.001"],
    "dridex": ["T1566.001", "T1059.001"],
    "formbook": ["T1056.001", "T1071.001"],
    "agent tesla": ["T1056.001", "T1071.001"],
    "agenttesla": ["T1056.001", "T1071.001"],
    "redline": ["T1003", "T1005"],
    "raccoon stealer": ["T1003", "T1005"],
    "vidar": ["T1003", "T1005"],
    "lumma": ["T1003", "T1005"],
    "stealer": ["T1003", "T1005"],
    "infostealer": ["T1003", "T1005"],
    "info-stealer": ["T1003", "T1005"],
    "banking trojan": ["T1185", "T1056"],
    "botnet": ["T1071", "T1583.005"],
    "mirai": ["T1190", "T1499"],
    "mozi": ["T1190", "T1499"],
    "gafgyt": ["T1190", "T1499"],
    "malware url": ["T1204.001", "T1105"],
    "malware site": ["T1204.001", "T1105"],
    "phishing url": ["T1566.002"],
    "phishing site": ["T1566.002"],
    "malicious payload": ["T1105", "T1204"],
    "exe distribution": ["T1204.002"],
    "dll distribution": ["T1204.002"],
    "maldoc": ["T1204.002", "T1566.001"],

    # ─── Network Attack / AbuseIPDB Patterns ─────────────
    # (critical for AbuseIPDB data which makes up 23% of intel)
    "brute force attack": ["T1110"],
    "ssh brute": ["T1110.001"],
    "rdp brute": ["T1110.001"],
    "scanning": ["T1595", "T1046"],
    "port scanning": ["T1046"],
    "mass scanning": ["T1595"],
    "vulnerability scanning": ["T1595.002"],
    "exploitation attempt": ["T1190"],
    "exploit attempt": ["T1190"],
    "malicious ip": ["T1071"],
    "known attacker": ["T1071"],
    "known botnet": ["T1583.005"],
    "spam": ["T1566"],
    "web attack": ["T1190"],
    "web application attack": ["T1190"],

    # ─── Common Threat Actor TTPs ────────────────────────
    "spyware": ["T1005", "T1056"],
    "adware": ["T1204"],
    "trojan": ["T1204.002"],
    "worm": ["T1080"],
    "exploit kit": ["T1189"],
    "zero day": ["T1190", "T1203"],
    "zero-day": ["T1190", "T1203"],
    "0day": ["T1190", "T1203"],
    "living off the land": ["T1218"],
    "lolbin": ["T1218"],
    "fileless": ["T1059.001", "T1055"],
    "fileless malware": ["T1059.001", "T1055"],
    "data encrypted for impact": ["T1486"],
    "account manipulation": ["T1098"],
    "access control": ["T1068"],
    "remote access": ["T1219"],
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
