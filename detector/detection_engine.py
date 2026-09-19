# detector/detection_engine.py

from .rules import (
    check_task_mismatch,
    check_sensitive_access,
    check_unexpected_tool,
    check_cross_system_movement,
    check_untrusted_to_sensitive_transition,
    check_task_change
)

from .scoring import (
    calculate_risk_score,
    get_risk_level
)


def build_evidence(events):

    evidence = []

    # ------------------------------------------------
    # Task change
    # ------------------------------------------------

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

    # ------------------------------------------------
    # Individual event evidence
    # ------------------------------------------------

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

        if source in {
            "external_document",
            "external_email",
            "external_share",
            "webpage",
            "external_url",
            "unknown"
        }:

            evidence.append({
                "type": "UNTRUSTED_SOURCE",
                "event_id": event_id,
                "description": (
                    f"Activity originated from "
                    f"untrusted source '{source}'."
                )
            })

    # ------------------------------------------------
    # Untrusted → sensitive transition
    # ------------------------------------------------

    if check_untrusted_to_sensitive_transition(events):

        evidence.append({
            "type": "UNTRUSTED_TO_SENSITIVE_TRANSITION",
            "description": (
                "Agent processed untrusted content "
                "before accessing a sensitive system."
            )
        })

    return evidence


def analyze_events(events):

    if not events:

        return {
            "agent_id": None,
            "task": None,
            "risk_level": "NORMAL",
            "risk_score": 0,
            "reasons": [],
            "attack_chain": [],
            "evidence": []
        }

    task_mismatch = False
    unexpected_tool = False
    sensitive_access = False

    reasons = []

    # ------------------------------------------------
    # Individual event analysis
    # ------------------------------------------------

    for event in events:

        if check_task_mismatch(event):
            task_mismatch = True

        if check_unexpected_tool(event):
            unexpected_tool = True

        if check_sensitive_access(event):
            sensitive_access = True

    # ------------------------------------------------
    # Sequence analysis
    # ------------------------------------------------

    cross_system_movement = (
        check_cross_system_movement(events)
    )

    untrusted_to_sensitive = (
        check_untrusted_to_sensitive_transition(events)
    )

    task_changed = check_task_change(events)

    # ------------------------------------------------
    # Reasons
    # ------------------------------------------------

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

    # ------------------------------------------------
    # Score
    # ------------------------------------------------

    risk_score = calculate_risk_score(
        task_mismatch=task_mismatch,
        unexpected_tool=unexpected_tool,
        sensitive_access=sensitive_access,
        cross_system_movement=cross_system_movement,
        untrusted_to_sensitive=untrusted_to_sensitive,
        task_changed=task_changed
    )

    risk_level = get_risk_level(risk_score)

    # ------------------------------------------------
    # Attack chain
    # ------------------------------------------------

    attack_chain = []

    for event in events:

        tool = event.get("tool")

        if tool and tool not in attack_chain:
            attack_chain.append(tool)

    # ------------------------------------------------
    # Evidence
    # ------------------------------------------------

    evidence = build_evidence(events)

    # ------------------------------------------------
    # Final result
    # ------------------------------------------------

    return {
        "agent_id": events[0].get("agent_id"),
        "task": events[0].get("task"),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": reasons,
        "attack_chain": attack_chain,
        "evidence": evidence
    }