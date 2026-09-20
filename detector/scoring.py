# detector/scoring.py

"""
AgentTrace Risk Scoring

The score is a prototype behavioral-risk score.
It is NOT a standardized cybersecurity severity score.

The score combines independent signals observed in an
AI-agent execution sequence.
"""


def calculate_risk_score(
    task_mismatch=False,
    unexpected_tool=False,
    sensitive_access=False,
    cross_system_movement=False,
    untrusted_to_sensitive=False,
):
    """
    Calculate a prototype behavioral risk score.

    Signals:

        Task/action mismatch
            +20

        Unexpected tool
            +20

        Sensitive resource access
            +25

        Cross-system movement
            +20

        Untrusted content followed by sensitive activity
            +25

    Maximum theoretical score = 110.
    The final score is capped at 100.
    """

    score = 0

    # --------------------------------------------------------
    # Task / action mismatch
    # --------------------------------------------------------

    if task_mismatch:
        score += 20

    # --------------------------------------------------------
    # Unexpected tool usage
    # --------------------------------------------------------

    if unexpected_tool:
        score += 20

    # --------------------------------------------------------
    # Sensitive resource access
    # --------------------------------------------------------

    if sensitive_access:
        score += 25

    # --------------------------------------------------------
    # Cross-system movement
    # --------------------------------------------------------

    if cross_system_movement:
        score += 20

    # --------------------------------------------------------
    # Untrusted → sensitive transition
    # --------------------------------------------------------

    if untrusted_to_sensitive:
        score += 25

    # --------------------------------------------------------
    # Cap score
    # --------------------------------------------------------

    return min(score, 100)


def get_risk_level(score):
    """
    Convert the prototype risk score into a severity level.
    """

    if score >= 80:
        return "HIGH"

    if score >= 60:
        return "MEDIUM"

    if score >= 30:
        return "LOW"

    return "NORMAL"