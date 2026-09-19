def calculate_risk_score(
    task_mismatch=False,
    unexpected_tool=False,
    sensitive_access=False,
    cross_system_movement=False
):
    score = 0

    if task_mismatch:
        score += 30

    if unexpected_tool:
        score += 20

    if sensitive_access:
        score += 30

    if cross_system_movement:
        score += 20

    return min(score, 100)


def get_risk_level(score):
    if score >= 80:
        return "HIGH"

    if score >= 60:
        return "MEDIUM"

    if score >= 30:
        return "LOW"

    return "NORMAL"