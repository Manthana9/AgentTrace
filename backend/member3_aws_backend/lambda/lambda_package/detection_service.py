# detection_service.py

"""
AgentTrace AWS Detection Service

Analyzes AI-agent event sequences to detect behavioral deviation
that may indicate Living-Off-the-Agent (LOTA) activity.

Core principle:

    The legitimate task can remain unchanged.

    Suspicious behavior is detected when the agent begins using
    unexpected tools, accessing sensitive systems, or moving
    across systems after processing untrusted content.
"""

from __future__ import annotations

from typing import Any, Dict, List


# ============================================================
# EXPECTED AGENT WORKFLOWS
# ============================================================

EXPECTED_TOOLS = {
    "summarize_email": {
        "email_tool",
        "drive_tool",
    }
}


# ============================================================
# TOOL ALIASES
# ============================================================

TOOL_ALIASES = {
    "email": "email_tool",
    "drive": "drive_tool",
    "github": "github_tool",
    "database": "database_tool",
    "internal_api": "internal_api_tool",
    "spreadsheet": "spreadsheet_tool",
}


def normalize_tool(tool: Any) -> str | None:
    """
    Normalize local simulator and dashboard tool names
    into one canonical representation.
    """

    if not tool:
        return None

    tool = str(tool).strip().lower()

    return TOOL_ALIASES.get(tool, tool)


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
    "internal-repo",
}


# ============================================================
# SENSITIVE TOOLS
# ============================================================

SENSITIVE_TOOLS = {
    "github_tool",
    "database_tool",
    "internal_api_tool",
    "credential_store",
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
# RULE 1 — TASK / ACTION MISMATCH
# ============================================================

def check_task_mismatch(event: Dict[str, Any]) -> bool:
    """
    Detect an action/tool that is outside the expected workflow
    for the current task.
    """

    task = event.get("task")
    tool = normalize_tool(event.get("tool"))

    expected_tools = {
        normalize_tool(item)
        for item in EXPECTED_TOOLS.get(task, set())
    }

    if expected_tools and tool not in expected_tools:
        return True

    return False


# ============================================================
# RULE 2 — UNEXPECTED TOOL
# ============================================================

def check_unexpected_tool(event: Dict[str, Any]) -> bool:
    """
    Detect unexpected tool usage.

    Kept separate from check_task_mismatch so the detector
    can expose both concepts independently.
    """

    return check_task_mismatch(event)


# ============================================================
# RULE 3 — SENSITIVE RESOURCE ACCESS
# ============================================================

def check_sensitive_access(event: Dict[str, Any]) -> bool:
    """
    Detect access to sensitive targets or sensitive tools.
    """

    target = event.get("target")
    tool = normalize_tool(event.get("tool"))

    normalized_target = (
        str(target).strip().lower()
        if target
        else None
    )

    if normalized_target in SENSITIVE_TARGETS:
        return True

    if tool in SENSITIVE_TOOLS:
        return True

    return False


# ============================================================
# RULE 4 — CROSS-SYSTEM MOVEMENT
# ============================================================

def check_cross_system_movement(
    events: List[Dict[str, Any]]
) -> bool:
    """
    Detect movement across three or more distinct systems/tools.
    """

    tools = []

    for event in events:

        tool = normalize_tool(
            event.get("tool")
        )

        if tool and tool not in tools:
            tools.append(tool)

    return len(tools) >= 3


# ============================================================
# RULE 5 — UNTRUSTED → SENSITIVE TRANSITION
# ============================================================

def check_untrusted_to_sensitive_transition(
    events: List[Dict[str, Any]]
) -> bool:
    """
    Detect sensitive activity after the agent has processed
    content from an untrusted source.
    """

    untrusted_seen = False

    for event in events:

        source = event.get("source")

        tool = normalize_tool(
            event.get("tool")
        )

        target = event.get("target")

        normalized_target = (
            str(target).strip().lower()
            if target
            else None
        )

        # ----------------------------------------------------
        # Untrusted content encountered
        # ----------------------------------------------------

        if source in UNTRUSTED_SOURCES:

            untrusted_seen = True

            continue

        # ----------------------------------------------------
        # Sensitive activity after untrusted content
        # ----------------------------------------------------

        if untrusted_seen:

            if (
                tool in SENSITIVE_TOOLS
                or normalized_target in SENSITIVE_TARGETS
            ):
                return True

    return False


# ============================================================
# RISK SCORING
# ============================================================

def calculate_risk_score(
    task_mismatch: bool = False,
    unexpected_tool: bool = False,
    sensitive_access: bool = False,
    cross_system_movement: bool = False,
    untrusted_to_sensitive: bool = False,
) -> int:
    """
    Calculate a prototype behavioral-risk score.

    This is an AgentTrace prototype score, not a
    standardized cybersecurity severity score.

    Signals:

        Task/action mismatch              +20
        Unexpected tool                   +20
        Sensitive resource access         +25
        Cross-system movement             +20
        Untrusted → sensitive transition  +25

    Maximum theoretical score = 110.
    Final score is capped at 100.
    """

    score = 0

    if task_mismatch:
        score += 20

    if unexpected_tool:
        score += 20

    if sensitive_access:
        score += 25

    if cross_system_movement:
        score += 20

    if untrusted_to_sensitive:
        score += 25

    return min(score, 100)


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score: int) -> str:

    if score >= 80:
        return "HIGH"

    if score >= 60:
        return "MEDIUM"

    if score >= 30:
        return "LOW"

    return "NORMAL"


# ============================================================
# EVIDENCE
# ============================================================

def build_evidence(
    events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:

    evidence = []

    if not events:
        return evidence

    # --------------------------------------------------------
    # Task and workflow
    # --------------------------------------------------------

    task = events[0].get("task")

    expected_tools = {
        normalize_tool(tool)
        for tool in EXPECTED_TOOLS.get(task, set())
    }

    observed_tools = []

    for event in events:

        tool = normalize_tool(
            event.get("tool")
        )

        if tool and tool not in observed_tools:
            observed_tools.append(tool)

    unexpected_tools = [
        tool
        for tool in observed_tools
        if tool not in expected_tools
    ]

    # --------------------------------------------------------
    # Expected vs observed behavior
    # --------------------------------------------------------

    if unexpected_tools:

        evidence.append({
            "type": "BEHAVIOR_DEVIATION",
            "description": (
                f"Task '{task}' expected tools "
                f"{sorted(expected_tools)}, but the agent "
                f"also invoked unexpected tools: "
                f"{unexpected_tools}."
            ),
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

        # ----------------------------------------------------
        # Unexpected tool
        # ----------------------------------------------------

        if check_unexpected_tool(event):

            evidence.append({
                "type": "UNEXPECTED_TOOL",
                "event_id": event_id,
                "description": (
                    f"Task '{task}' invoked unexpected "
                    f"tool '{tool}'."
                ),
            })

        # ----------------------------------------------------
        # Sensitive resource
        # ----------------------------------------------------

        if check_sensitive_access(event):

            evidence.append({
                "type": "SENSITIVE_RESOURCE_ACCESS",
                "event_id": event_id,
                "description": (
                    f"Agent performed '{action}' using "
                    f"'{tool}' against sensitive target "
                    f"'{target}'."
                ),
            })

        # ----------------------------------------------------
        # Untrusted source
        # ----------------------------------------------------

        if source in UNTRUSTED_SOURCES:

            evidence.append({
                "type": "UNTRUSTED_SOURCE",
                "event_id": event_id,
                "description": (
                    f"Agent processed content from "
                    f"untrusted source '{source}'."
                ),
            })

    # --------------------------------------------------------
    # Cross-system movement
    # --------------------------------------------------------

    if check_cross_system_movement(events):

        evidence.append({
            "type": "CROSS_SYSTEM_MOVEMENT",
            "description": (
                "The agent moved across multiple systems "
                "during a single task execution."
            ),
        })

    # --------------------------------------------------------
    # Untrusted → sensitive
    # --------------------------------------------------------

    if check_untrusted_to_sensitive_transition(events):

        evidence.append({
            "type": "UNTRUSTED_TO_SENSITIVE_TRANSITION",
            "description": (
                "The agent processed untrusted content "
                "before accessing a sensitive system."
            ),
        })

    # --------------------------------------------------------
    # Same task, changed behavior
    # --------------------------------------------------------

    if unexpected_tools:

        evidence.append({
            "type": "TASK_ACTION_DEVIATION",
            "description": (
                f"The task remained '{task}', but the "
                "agent's tool usage deviated from the "
                "expected workflow."
            ),
        })

    return evidence


# ============================================================
# MAIN AWS DETECTION FUNCTION
# ============================================================

def analyze_sequence(
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:

    # --------------------------------------------------------
    # Empty sequence
    # --------------------------------------------------------

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
            "expected_workflow": [],
            "observed_workflow": [],
            "event_ids": [],
            "evidence": [],
        }

    # --------------------------------------------------------
    # Basic information
    # --------------------------------------------------------

    agent_id = events[0].get("agent_id")
    task = events[0].get("task")

    # --------------------------------------------------------
    # Individual signals
    # --------------------------------------------------------

    task_mismatch = False
    unexpected_tool = False
    sensitive_access = False

    for event in events:

        if check_task_mismatch(event):
            task_mismatch = True

        if check_unexpected_tool(event):
            unexpected_tool = True

        if check_sensitive_access(event):
            sensitive_access = True

    # --------------------------------------------------------
    # Sequence signals
    # --------------------------------------------------------

    cross_system_movement = (
        check_cross_system_movement(events)
    )

    untrusted_to_sensitive = (
        check_untrusted_to_sensitive_transition(events)
    )

    # --------------------------------------------------------
    # IMPORTANT
    #
    # We intentionally do NOT check task_changed.
    #
    # The AgentTrace attack model assumes the legitimate task
    # remains unchanged while the agent's behavior is manipulated.
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Reason codes
    # --------------------------------------------------------

    reasons = []

    if task_mismatch:
        reasons.append(
            "TASK_MISMATCH"
        )

    if unexpected_tool:
        reasons.append(
            "UNEXPECTED_TOOL"
        )

    if sensitive_access:
        reasons.append(
            "SENSITIVE_RESOURCE_ACCESS"
        )

    if cross_system_movement:
        reasons.append(
            "CROSS_SYSTEM_MOVEMENT"
        )

    if untrusted_to_sensitive:
        reasons.append(
            "UNTRUSTED_TO_SENSITIVE_TRANSITION"
        )

    # --------------------------------------------------------
    # Risk score
    # --------------------------------------------------------

    risk_score = calculate_risk_score(
        task_mismatch=task_mismatch,
        unexpected_tool=unexpected_tool,
        sensitive_access=sensitive_access,
        cross_system_movement=cross_system_movement,
        untrusted_to_sensitive=untrusted_to_sensitive,
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
    # Expected workflow
    # --------------------------------------------------------

    expected_workflow = list(
        EXPECTED_TOOLS.get(
            task,
            set()
        )
    )

    # --------------------------------------------------------
    # Observed workflow
    # --------------------------------------------------------

    observed_workflow = attack_chain.copy()

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
    # Final response
    # --------------------------------------------------------

    return {
        "agent_id": agent_id,

        "task": task,

        "risk_level": risk_level,

        "risk_score": risk_score,

        "status": status,

        "reasons": reasons,

        "reason_codes": reasons,

        "expected_workflow": expected_workflow,

        "observed_workflow": observed_workflow,

        "attack_chain": attack_chain,

        "event_ids": [
            event.get("event_id")
            for event in events
        ],

        "evidence": evidence,
    }