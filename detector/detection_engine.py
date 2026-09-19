# detector/detection_engine.py

from .rules import (
    check_task_mismatch,
    check_sensitive_access,
    check_unexpected_tool,
    check_cross_system_movement,
    check_untrusted_to_sensitive_transition
)

from .scoring import (
    calculate_risk_score,
    get_risk_level
)

def build_evidence(events):
    """
    Build human-readable evidence explaining
    why the detector generated an alert.
    """

    evidence = []

    for event in events:

        event_id = event.get("event_id")
        task = event.get("task")
        tool = event.get("tool")
        action = event.get("action")
        target = event.get("target")
        source = event.get("source")

        # Task mismatch evidence
        if check_task_mismatch(event):

            evidence.append({
                "type": "TASK_MISMATCH",
                "event_id": event_id,
                "description": (
                    f"Task '{task}' used unexpected tool "
                    f"'{tool}'."
                )
            })

        # Sensitive resource evidence
        if check_sensitive_access(event):

            evidence.append({
                "type": "SENSITIVE_RESOURCE_ACCESS",
                "event_id": event_id,
                "description": (
                    f"Agent performed '{action}' using "
                    f"'{tool}' against sensitive target "
                    f"'{target}'."
                )
            })

        # Untrusted source evidence
        if source in {
            "external_document",
            "external_email",
            "webpage",
            "external_url",
            "unknown"
        }:

            evidence.append({
                "type": "UNTRUSTED_SOURCE",
                "event_id": event_id,
                "description": (
                    f"Activity originated from untrusted "
                    f"source '{source}'."
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

    # -----------------------------------------
    # Analyze individual events
    # -----------------------------------------

    for event in events:

        if check_task_mismatch(event):
            task_mismatch = True

        if check_unexpected_tool(event):
            unexpected_tool = True

        if check_sensitive_access(event):
            sensitive_access = True

    # -----------------------------------------
    # Analyze sequence
    # -----------------------------------------

    cross_system_movement = check_cross_system_movement(
        events
    )

    untrusted_to_sensitive = (
        check_untrusted_to_sensitive_transition(events)
    )

    # -----------------------------------------
    # Build reasons
    # -----------------------------------------

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

    # -----------------------------------------
    # Calculate score
    # -----------------------------------------

    risk_score = calculate_risk_score(
        task_mismatch=task_mismatch,
        unexpected_tool=unexpected_tool,
        sensitive_access=sensitive_access,
        cross_system_movement=cross_system_movement,
        untrusted_to_sensitive=untrusted_to_sensitive
    )

    risk_level = get_risk_level(risk_score)

    # -----------------------------------------
    # Build attack chain
    # -----------------------------------------

    attack_chain = []

    for event in events:

        tool = event.get("tool")

        if tool and tool not in attack_chain:
            attack_chain.append(tool)

    # -----------------------------------------
    # Build evidence
    # -----------------------------------------

    evidence = build_evidence(events)

    # -----------------------------------------
    # Final result
    # -----------------------------------------

    return {
        "agent_id": events[0].get("agent_id"),
        "task": events[0].get("task"),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": reasons,
        "attack_chain": attack_chain,
        "evidence": evidence
    }


# =====================================================
# TEST
# =====================================================

if __name__ == "__main__":

    test_events = [

        {
            "event_id": "evt_001",
            "agent_id": "research-agent-01",
            "task": "summarize_email",
            "tool": "email",
            "action": "read",
            "target": "inbox",
            "source": "user"
        },

        {
            "event_id": "evt_002",
            "agent_id": "research-agent-01",
            "task": "summarize_email",
            "tool": "drive",
            "action": "read",
            "target": "project_document",
            "source": "external_document"
        },

        {
            "event_id": "evt_003",
            "agent_id": "research-agent-01",
            "task": "summarize_email",
            "tool": "github",
            "action": "read_repository",
            "target": "private_repository",
            "source": "external_document"
        },

        {
            "event_id": "evt_004",
            "agent_id": "research-agent-01",
            "task": "summarize_email",
            "tool": "database",
            "action": "query",
            "target": "database",
            "source": "github"
        }
    ]

    result = analyze_events(test_events)

    print("\n===== AgentTrace Detection Result =====\n")

    print("Agent ID:")
    print(result["agent_id"])

    print("\nTask:")
    print(result["task"])

    print("\nRisk Level:")
    print(result["risk_level"])

    print("\nRisk Score:")
    print(result["risk_score"])

    print("\nReasons:")

    for reason in result["reasons"]:
        print("-", reason)

    print("\nAttack Chain:")

    print(" -> ".join(result["attack_chain"]))

    print("\nEvidence:")

    for item in result["evidence"]:
        print(
            f"- [{item['type']}] "
            f"{item['event_id']}: "
            f"{item['description']}"
        )

    print("\n========================================\n")