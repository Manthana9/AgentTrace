# detector/detection_engine.py

from rules import (
    check_task_mismatch,
    check_sensitive_access,
    check_unexpected_tool,
    check_cross_system_movement
)

from scoring import (
    calculate_risk_score,
    get_risk_level
)


def analyze_events(events):
    """
    Analyze a sequence of AI-agent activity events.

    Input:
        List of event dictionaries.

    Output:
        Detection result containing:
        - agent ID
        - task
        - risk level
        - risk score
        - reasons
        - attack chain
    """

    # Handle empty input
    if not events:
        return {
            "agent_id": None,
            "task": None,
            "risk_level": "NORMAL",
            "risk_score": 0,
            "reasons": [],
            "attack_chain": []
        }

    # Detection flags
    task_mismatch = False
    unexpected_tool = False
    sensitive_access = False

    reasons = []

    # --------------------------------------------------
    # Analyze individual events
    # --------------------------------------------------

    for event in events:

        if check_task_mismatch(event):
            task_mismatch = True

        if check_unexpected_tool(event):
            unexpected_tool = True

        if check_sensitive_access(event):
            sensitive_access = True

    # --------------------------------------------------
    # Analyze the complete sequence
    # --------------------------------------------------

    cross_system_movement = check_cross_system_movement(events)

    # --------------------------------------------------
    # Build detection reasons
    # --------------------------------------------------

    if task_mismatch:
        reasons.append("TASK_MISMATCH")

    if unexpected_tool:
        reasons.append("UNEXPECTED_TOOL")

    if sensitive_access:
        reasons.append("SENSITIVE_RESOURCE_ACCESS")

    if cross_system_movement:
        reasons.append("CROSS_SYSTEM_MOVEMENT")

    # --------------------------------------------------
    # Calculate risk
    # --------------------------------------------------

    risk_score = calculate_risk_score(
        task_mismatch=task_mismatch,
        unexpected_tool=unexpected_tool,
        sensitive_access=sensitive_access,
        cross_system_movement=cross_system_movement
    )

    risk_level = get_risk_level(risk_score)

    # --------------------------------------------------
    # Build attack chain
    # --------------------------------------------------

    attack_chain = []

    for event in events:

        tool = event.get("tool")

        if tool and tool not in attack_chain:
            attack_chain.append(tool)

    # --------------------------------------------------
    # Final detection result
    # --------------------------------------------------

    return {
        "agent_id": events[0].get("agent_id"),
        "task": events[0].get("task"),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": reasons,
        "attack_chain": attack_chain
    }


# ======================================================
# TESTING
# ======================================================

if __name__ == "__main__":

    # Simulated suspicious agent activity
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
        "source": "email"
    }
]
    # Run detector
    result = analyze_events(test_events)

    # Display result
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

    print("\n========================================\n")