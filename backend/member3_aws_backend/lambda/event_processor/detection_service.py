from __future__ import annotations

from typing import Any, Dict, List


# ============================================================
# EXPECTED AGENT WORKFLOWS
# ============================================================

EXPECTED_TOOLS = {
    "summarize_email": {
        "email_tool",
        "drive_tool",
        "email",
        "drive"
    }
}


# ============================================================
# SENSITIVE TARGETS
# ============================================================

SENSITIVE_TARGETS = {
    "credentials",
    "secrets",
    "database",
    "users_table",
    "private_repository",
    "org-repos",
    "internal_api",
    "internal-service",
    "internal-repo"
}


# ============================================================
# SENSITIVE TOOLS
# ============================================================

SENSITIVE_TOOLS = {
    "github_tool",
    "database_tool",
    "internal_api_tool",
    "credential_store",
    "github",
    "database",
    "internal_api"
}


# ============================================================
# UNTRUSTED SOURCES
# ============================================================

UNTRUSTED_SOURCES = {
    "external_document",
    "external_email",
    "external_share",
    "webpage",
    "external_url",
    "unknown",
}


# ============================================================
# RULE 1 — TASK MISMATCH
# ============================================================

def check_task_mismatch(event: Dict[str, Any]) -> bool:

    task = event.get("task")
    tool = event.get("tool")

    expected_tools = EXPECTED_TOOLS.get(
        task,
        set()
    )

    if expected_tools and tool not in expected_tools:
        return True

    return False


# ============================================================
# RULE 2 — UNEXPECTED TOOL
# ============================================================

def check_unexpected_tool(event: Dict[str, Any]) -> bool:

    task = event.get("task")
    tool = event.get("tool")

    expected_tools = EXPECTED_TOOLS.get(
        task,
        set()
    )

    if expected_tools and tool not in expected_tools:
        return True

    return False


# ============================================================
# RULE 3 — SENSITIVE RESOURCE ACCESS
# ============================================================

def check_sensitive_access(event: Dict[str, Any]) -> bool:

    target = event.get("target")

    return target in SENSITIVE_TARGETS


# ============================================================
# RULE 4 — CROSS-SYSTEM MOVEMENT
# ============================================================

def check_cross_system_movement(
    events: List[Dict[str, Any]]
) -> bool:

    tools = []

    for event in events:

        tool = event.get("tool")

        if tool and tool not in tools:
            tools.append(tool)

    return len(tools) >= 3


# ============================================================
# RULE 5 — UNTRUSTED → SENSITIVE TRANSITION
# ============================================================

def check_untrusted_to_sensitive_transition(
    events: List[Dict[str, Any]]
) -> bool:

    untrusted_seen = False

    for event in events:

        source = event.get("source")
        tool = event.get("tool")
        target = event.get("target")

        if source in UNTRUSTED_SOURCES:
            untrusted_seen = True

        if untrusted_seen:

            if (
                tool in SENSITIVE_TOOLS
                or target in SENSITIVE_TARGETS
            ):
                return True

    return False


# ============================================================
# RULE 6 — TASK CHANGE
# ============================================================

def check_task_change(
    events: List[Dict[str, Any]]
) -> bool:

    tasks = []

    for event in events:

        task = event.get("task")

        if task and task not in tasks:
            tasks.append(task)

    return len(tasks) > 1


# ============================================================
# RISK SCORING
# ============================================================

def calculate_risk_score(
    task_mismatch: bool = False,
    unexpected_tool: bool = False,
    sensitive_access: bool = False,
    cross_system_movement: bool = False,
    untrusted_to_sensitive: bool = False,
    task_changed: bool = False,
) -> int:

    score = 0

    if task_mismatch:
        score += 20

    if unexpected_tool:
        score += 15

    if sensitive_access:
        score += 20

    if cross_system_movement:
        score += 15

    if untrusted_to_sensitive:
        score += 20

    if task_changed:
        score += 25

    return min(score, 100)


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score: int) -> str:

    if score >= 80:
        return "HIGH"

    elif score >= 60:
        return "MEDIUM"

    elif score >= 30:
        return "LOW"

    return "NORMAL"


# ============================================================
# EVIDENCE
# ============================================================

def build_evidence(
    events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:

    evidence = []

    # --------------------------------------------------------
    # Task change evidence
    # --------------------------------------------------------

    tasks = []

    for event in events:

        task = event.get("task")

        if task and task not in tasks:
            tasks.append(task)

    if len(tasks) > 1:

        evidence.append({
            "type": "TASK_CHANGE",
            "description": (
                f"Agent task changed from "
                f"'{tasks[0]}' to '{tasks[-1]}'."
            )
        })

    # --------------------------------------------------------
    # Individual event evidence
    # --------------------------------------------------------

    for event in events:

        event_id = event.get("event_id")
        task = event.get("task")
        tool = event.get("tool")
        action = event.get("action")
        target = event.get("target")
        source = event.get("source")

        if check_task_mismatch(event):

            evidence.append({
                "type": "TASK_MISMATCH",
                "event_id": event_id,
                "description": (
                    f"Task '{task}' used unexpected "
                    f"tool '{tool}'."
                )
            })

        if check_sensitive_access(event):

            evidence.append({
                "type": "SENSITIVE_RESOURCE_ACCESS",
                "event_id": event_id,
                "description": (
                    f"Agent performed '{action}' using "
                    f"'{tool}' against '{target}'."
                )
            })

        if source in UNTRUSTED_SOURCES:

            evidence.append({
                "type": "UNTRUSTED_SOURCE",
                "event_id": event_id,
                "description": (
                    f"Activity originated from "
                    f"untrusted source '{source}'."
                )
            })

    # --------------------------------------------------------
    # Untrusted → sensitive transition evidence
    # --------------------------------------------------------

    if check_untrusted_to_sensitive_transition(events):

        evidence.append({
            "type": "UNTRUSTED_TO_SENSITIVE_TRANSITION",
            "description": (
                "Agent processed untrusted content "
                "before accessing a sensitive system."
            )
        })

    return evidence


# ============================================================
# MAIN DETECTION FUNCTION
# ============================================================

def analyze_sequence(
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:

    if not events:

        return {
            "agent_id": None,
            "task": None,
            "risk_level": "NORMAL",
            "risk_score": 0,
            "status": "Normal",
            "reasons": [],
            "reason_codes": [],
            "attack_chain": [],
            "event_ids": [],
            "evidence": [],
        }

    task_mismatch = False
    unexpected_tool = False
    sensitive_access = False

    reasons = []

    # --------------------------------------------------------
    # Individual event analysis
    # --------------------------------------------------------

    for event in events:

        if check_task_mismatch(event):
            task_mismatch = True

        if check_unexpected_tool(event):
            unexpected_tool = True

        if check_sensitive_access(event):
            sensitive_access = True

    # --------------------------------------------------------
    # Sequence analysis
    # --------------------------------------------------------

    cross_system_movement = (
        check_cross_system_movement(events)
    )

    untrusted_to_sensitive = (
        check_untrusted_to_sensitive_transition(events)
    )

    task_changed = check_task_change(events)

    # --------------------------------------------------------
    # Reason codes
    # --------------------------------------------------------

    if task_mismatch:
        reasons.append("TASK_MISMATCH")

    if unexpected_tool:
        reasons.append("UNEXPECTED_TOOL")

    if sensitive_access:
        reasons.append("SENSITIVE_RESOURCE_ACCESS")

    if cross_system_movement:
        reasons.append("CROSS_SYSTEM_MOVEMENT")

    if untrusted_to_sensitive:

        reasons.append(
            "UNTRUSTED_TO_SENSITIVE_TRANSITION"
        )

    if task_changed:
        reasons.append("TASK_CHANGED")

    # --------------------------------------------------------
    # Risk score
    # --------------------------------------------------------

    risk_score = calculate_risk_score(
        task_mismatch=task_mismatch,
        unexpected_tool=unexpected_tool,
        sensitive_access=sensitive_access,
        cross_system_movement=cross_system_movement,
        untrusted_to_sensitive=untrusted_to_sensitive,
        task_changed=task_changed,
    )

    risk_level = get_risk_level(
        risk_score
    )

    # --------------------------------------------------------
    # Attack chain
    # --------------------------------------------------------

    attack_chain = []

    for event in events:

        tool = event.get("tool")

        if tool and tool not in attack_chain:

            attack_chain.append(tool)

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    evidence = build_evidence(
        events
    )

    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    status = (
        "Potentially Suspicious"
        if reasons
        else "Normal"
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "agent_id": events[0].get("agent_id"),
        "task": events[0].get("task"),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "status": status,
        "reasons": reasons,
        "reason_codes": reasons,
        "attack_chain": attack_chain,
        "event_ids": [
            event.get("event_id")
            for event in events
        ],
        "evidence": evidence,
    }