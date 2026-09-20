"""
AgentTrace Detection Engine

Analyzes sequences of AI-agent tool calls to identify behavioral
deviation that may indicate Living-Off-the-Agent (LOTA) activity.

Important design principle:
The agent's legitimate task does NOT need to change.

An attacker may manipulate the agent while it continues operating
under the same task. AgentTrace therefore focuses on:

    - unexpected tools
    - sensitive resource access
    - cross-system movement
    - untrusted-to-sensitive transitions
    - task/action mismatch
"""

from .rules import (
    check_task_mismatch,
    check_sensitive_access,
    check_unexpected_tool,
    check_cross_system_movement,
    check_untrusted_to_sensitive_transition,
)

from .scoring import (
    calculate_risk_score,
    get_risk_level,
)


# ============================================================
# EXPECTED WORKFLOW
# ============================================================

EXPECTED_WORKFLOW = {
    "summarize_email": [
        "email_tool",
        "drive_tool",
    ]
}


# ============================================================
# TOOL NORMALIZATION
# ============================================================

def _normalize_tool(tool):
    """
    Normalize tool names so the detector can understand both:

        email_tool
        email

    This is useful because the local simulator and dashboard
    may represent tools slightly differently.
    """

    if not tool:
        return None

    tool = str(tool).strip().lower()

    aliases = {
        "email": "email_tool",
        "drive": "drive_tool",
        "github": "github_tool",
        "database": "database_tool",
        "internal_api": "internal_api_tool",
        "spreadsheet": "spreadsheet_tool",
    }

    return aliases.get(tool, tool)


# ============================================================
# EXPECTED TOOLS
# ============================================================

def _expected_tools_for_task(task):
    """
    Return the expected tools for a task.
    """

    tools = EXPECTED_WORKFLOW.get(task, [])

    return {
        _normalize_tool(tool)
        for tool in tools
    }


# ============================================================
# OBSERVED WORKFLOW
# ============================================================

def _build_attack_chain(events):
    """
    Build the ordered sequence of unique tools observed
    during the agent execution.
    """

    attack_chain = []

    for event in events:
        tool = _normalize_tool(event.get("tool"))

        if tool and tool not in attack_chain:
            attack_chain.append(tool)

    return attack_chain


# ============================================================
# BUILD EVIDENCE
# ============================================================

def build_evidence(events):

    evidence = []

    if not events:
        return evidence

    # --------------------------------------------------------
    # Task information
    # --------------------------------------------------------

    task = events[0].get("task")

    expected_tools = _expected_tools_for_task(task)

    observed_tools = []

    for event in events:
        tool = _normalize_tool(event.get("tool"))

        if tool and tool not in observed_tools:
            observed_tools.append(tool)

    # --------------------------------------------------------
    # Expected vs observed workflow
    # --------------------------------------------------------

    unexpected_tools = [
        tool
        for tool in observed_tools
        if tool not in expected_tools
    ]

    if unexpected_tools:

        evidence.append({
            "type": "BEHAVIOR_DEVIATION",
            "description": (
                f"Task '{task}' expected tools "
                f"{sorted(expected_tools)}, but observed "
                f"unexpected tools: {unexpected_tools}."
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
        # Task mismatch
        # ----------------------------------------------------

        if check_task_mismatch(event):

            evidence.append({
                "type": "TASK_MISMATCH",
                "event_id": event_id,
                "description": (
                    f"Task '{task}' used unexpected "
                    f"tool '{tool}'."
                ),
            })

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
        # Sensitive resource access
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

        if source in {
            "external_document",
            "external_email",
            "external_share",
            "webpage",
            "external_url",
            "unknown",
        }:

            evidence.append({
                "type": "UNTRUSTED_SOURCE",
                "event_id": event_id,
                "description": (
                    f"Agent processed content from "
                    f"untrusted source '{source}' "
                    f"before subsequent actions."
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
    # Untrusted → sensitive transition
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
# ANALYZE EVENTS
# ============================================================

def analyze_events(events):

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
            "evidence": [],
        }

    # --------------------------------------------------------
    # Basic task information
    # --------------------------------------------------------

    agent_id = events[0].get("agent_id")
    task = events[0].get("task")

    expected_tools = _expected_tools_for_task(task)

    # --------------------------------------------------------
    # Individual event analysis
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
    # Sequence analysis
    # --------------------------------------------------------

    cross_system_movement = check_cross_system_movement(events)

    untrusted_to_sensitive = (
        check_untrusted_to_sensitive_transition(events)
    )

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # We deliberately do NOT use task_changed here.
    #
    # The attacker does not need to change the task.
    # The suspicious behavior is the deviation in tool usage.
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Reasons
    # --------------------------------------------------------

    reasons = []

    if task_mismatch:
        reasons.append("TASK_MISMATCH")

    if unexpected_tool:
        reasons.append("UNEXPECTED_TOOL")

    if sensitive_access:
        reasons.append("SENSITIVE_RESOURCE_ACCESS")

    if cross_system_movement:
        reasons.append("CROSS_SYSTEM_MOVEMENT")

    if untrusted_to_sensitive:
        reasons.append("UNTRUSTED_TO_SENSITIVE_TRANSITION")

    # --------------------------------------------------------
    # Score
    # --------------------------------------------------------

    risk_score = calculate_risk_score(
        task_mismatch=task_mismatch,
        unexpected_tool=unexpected_tool,
        sensitive_access=sensitive_access,
        cross_system_movement=cross_system_movement,
        untrusted_to_sensitive=untrusted_to_sensitive,
    )

    risk_level = get_risk_level(risk_score)

    # --------------------------------------------------------
    # Attack chain
    # --------------------------------------------------------

    attack_chain = _build_attack_chain(events)

    # --------------------------------------------------------
    # Expected workflow
    # --------------------------------------------------------

    # Keep the configured workflow order deterministic.
    expected_workflow = [
        _normalize_tool(tool)
        for tool in EXPECTED_WORKFLOW.get(task, [])
    ]

    # --------------------------------------------------------
    # Observed workflow
    # --------------------------------------------------------

    observed_workflow = attack_chain.copy()

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    evidence = build_evidence(events)

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    if risk_score > 0:
        status = "Potentially Suspicious"
    else:
        status = "Normal"

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "agent_id": agent_id,
        "task": task,

        "status": status,

        "risk_level": risk_level,
        "risk_score": risk_score,

        "reasons": reasons,
        "reason_codes": reasons,

        "expected_workflow": expected_workflow,
        "observed_workflow": observed_workflow,

        "attack_chain": attack_chain,

        "evidence": evidence,
    }