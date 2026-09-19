from rules import (
    check_task_mismatch,
    check_sensitive_access,
    check_unexpected_tool
)

from scoring import calculate_risk_score, get_risk_level


def analyze_event(event):

    task_mismatch = check_task_mismatch(event)

    unexpected_tool = check_unexpected_tool(event)

    sensitive_access = check_sensitive_access(event)

    cross_system_movement = False

    score = calculate_risk_score(
        task_mismatch=task_mismatch,
        unexpected_tool=unexpected_tool,
        sensitive_access=sensitive_access,
        cross_system_movement=cross_system_movement
    )

    risk_level = get_risk_level(score)

    reasons = []

    if task_mismatch:
        reasons.append("TASK_MISMATCH")

    if unexpected_tool:
        reasons.append("UNEXPECTED_TOOL")

    if sensitive_access:
        reasons.append("SENSITIVE_RESOURCE_ACCESS")

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons
    }
if __name__ == "__main__":

    test_event = {
        "event_id": "evt_001",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "github",
        "action": "read_repository",
        "target": "private_repository",
        "source": "external_document"
    }

    result = analyze_event(test_event)

    print(result)