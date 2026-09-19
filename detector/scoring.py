# detector/scoring.py


def calculate_risk_score(
    task_mismatch=False,
    unexpected_tool=False,
    sensitive_access=False,
    cross_system_movement=False,
    untrusted_to_sensitive=False
):
    score = 0

    if task_mismatch:
        score += 25

    if unexpected_tool:
        score += 15

    if sensitive_access:
        score += 25

    if cross_system_movement:
        score += 15

    if untrusted_to_sensitive:
        score += 20

    return min(score, 100)


def get_risk_level(score):

    if score >= 80:
        return "HIGH"

    elif score >= 60:
        return "MEDIUM"

    elif score >= 30:
        return "LOW"

    else:
        return "NORMAL"