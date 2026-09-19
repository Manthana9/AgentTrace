# detector/scoring.py


def calculate_risk_score(
    task_mismatch=False,
    unexpected_tool=False,
    sensitive_access=False,
    cross_system_movement=False
):
    """
    Calculates the prototype risk score.

    Scoring:
    Task mismatch             = +30
    Unexpected tool           = +20
    Sensitive resource access = +30
    Cross-system movement     = +20
    """

    score = 0

    if task_mismatch:
        score += 30

    if unexpected_tool:
        score += 20

    if sensitive_access:
        score += 30

    if cross_system_movement:
        score += 20

    # Maximum score is 100
    return min(score, 100)


def get_risk_level(score):
    """
    Converts the numerical score into a risk level.
    """

    if score >= 80:
        return "HIGH"

    elif score >= 60:
        return "MEDIUM"

    elif score >= 30:
        return "LOW"

    else:
        return "NORMAL"