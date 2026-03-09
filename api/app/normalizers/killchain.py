"""Kill Chain phase mapping — ATT&CK tactics to Unified Kill Chain phases.

Maps MITRE ATT&CK tactic IDs/names to the Lockheed Martin Cyber Kill
Chain phases and the Unified Kill Chain model. Parses the ``T1234.001 -
Technique Name`` format stored in ``tactics_techniques`` fields.
"""

from __future__ import annotations

import re

# Regex to parse technique strings: "T1566.001 - Phishing: Spear..."
_TECHNIQUE_RE = re.compile(
    r"^(T\d{4}(?:\.\d{3})?)\s*[-–—]\s*(.+)$",
    re.IGNORECASE,
)

# ── ATT&CK Tactic → Kill Chain Phase mapping ────────────
# Maps ATT&CK tactic slugs (lowercase) to Unified Kill Chain phases
TACTIC_TO_PHASE: dict[str, str] = {
    "reconnaissance":       "Reconnaissance",
    "resource-development":  "Weaponisation",
    "initial-access":        "Delivery",
    "execution":             "Exploitation",
    "persistence":           "Installation",
    "privilege-escalation":  "Exploitation",
    "defense-evasion":       "Installation",
    "credential-access":     "Exploitation",
    "discovery":             "Command & Control",
    "lateral-movement":      "Command & Control",
    "collection":            "Actions on Objectives",
    "command-and-control":   "Command & Control",
    "exfiltration":          "Actions on Objectives",
    "impact":                "Actions on Objectives",
}

# Reverse map: all known tactic display names → slugs
_TACTIC_LABELS: dict[str, str] = {
    "Reconnaissance":       "reconnaissance",
    "Resource Development":  "resource-development",
    "Initial Access":        "initial-access",
    "Execution":             "execution",
    "Persistence":           "persistence",
    "Privilege Escalation":  "privilege-escalation",
    "Defense Evasion":       "defense-evasion",
    "Credential Access":     "credential-access",
    "Discovery":             "discovery",
    "Lateral Movement":      "lateral-movement",
    "Collection":            "collection",
    "Command and Control":   "command-and-control",
    "Exfiltration":          "exfiltration",
    "Impact":                "impact",
}

# Ordered kill chain phases (Unified Kill Chain / Lockheed Martin hybrid)
KILL_CHAIN_PHASES: list[str] = [
    "Reconnaissance",
    "Weaponisation",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]


def parse_technique(raw: str) -> tuple[str | None, str | None]:
    """Parse ``"T1566.001 - Phishing: Spearphishing"`` → (technique_id, name).

    Returns (None, None) if the string doesn't match the expected format.
    """
    m = _TECHNIQUE_RE.match(raw.strip())
    if m:
        return m.group(1).upper(), m.group(2).strip()
    return None, None


def tactic_to_phase(tactic: str) -> str:
    """Map a MITRE ATT&CK tactic (slug or label) to a kill chain phase.

    Returns ``"Unknown"`` if the tactic is not recognised.
    """
    slug = tactic.strip().lower()
    if slug in TACTIC_TO_PHASE:
        return TACTIC_TO_PHASE[slug]

    # Try label → slug → phase
    label_slug = _TACTIC_LABELS.get(tactic.strip())
    if label_slug and label_slug in TACTIC_TO_PHASE:
        return TACTIC_TO_PHASE[label_slug]

    return "Unknown"


def map_techniques_to_phases(
    tactics_techniques: list[str],
) -> dict[str, list[dict]]:
    """Map a list of technique strings to kill chain phases.

    Args:
        tactics_techniques: List of ``"T1234.001 - Technique Name"`` strings.

    Returns:
        Dict keyed by kill chain phase, each containing a list of technique dicts::

            {
                "Delivery": [{"id": "T1566.001", "name": "Phishing: Spear..."}],
                "Exploitation": [{"id": "T1059", "name": "Command Scripting"}],
            }
    """
    phases: dict[str, list[dict]] = {}

    for raw in tactics_techniques:
        tech_id, tech_name = parse_technique(str(raw))
        if not tech_id:
            continue

        # Infer phase: no tactic slug available in the string, so we mark
        # as "Unmapped" — the caller should resolve via AttackTechnique DB lookup
        entry = {"id": tech_id, "name": tech_name or tech_id}
        phases.setdefault("Unmapped", []).append(entry)

    return phases


def map_techniques_with_tactics(
    techniques: list[dict],
) -> dict[str, list[dict]]:
    """Map techniques that include tactic information to kill chain phases.

    Args:
        techniques: List of dicts with ``id``, ``name``, and ``tactic`` keys
                    (as returned by AttackTechnique DB query).

    Returns:
        Dict keyed by kill chain phase with technique entries.
    """
    phases: dict[str, list[dict]] = {}

    for tech in techniques:
        tactic = tech.get("tactic", "")
        phase = tactic_to_phase(tactic)
        entry = {
            "id": tech.get("id", ""),
            "name": tech.get("name", ""),
            "tactic": tactic,
        }
        phases.setdefault(phase, []).append(entry)

    return phases


def kill_chain_coverage(
    phase_map: dict[str, list[dict]],
) -> dict[str, bool]:
    """Return a coverage dict indicating which kill chain phases are present.

    Useful for gap analysis — missing phases hint at incomplete intelligence.
    """
    return {
        phase: phase in phase_map and len(phase_map[phase]) > 0
        for phase in KILL_CHAIN_PHASES
    }


def coverage_score(phase_map: dict[str, list[dict]]) -> float:
    """Return 0.0–1.0 score indicating what fraction of kill chain phases are covered."""
    coverage = kill_chain_coverage(phase_map)
    covered = sum(1 for v in coverage.values() if v)
    return covered / len(KILL_CHAIN_PHASES)
