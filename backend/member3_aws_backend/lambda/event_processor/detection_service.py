from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections import Counter
from typing import Any, Dict, List


# Normal workflow for the AgentTrace prototype.
EXPECTED_TOOLS = {"email", "drive"}

# Tools/resources that may represent sensitive access.
SENSITIVE_TOOL_KEYWORDS = {
    "database",
    "internal_api",
    "credential",
    "credentials",
}

SENSITIVE_TEXT_KEYWORDS = {
    "credential",
    "credentials",
    "secret",
    "secrets",
    "password",
    "token",
    "private-key",
    "private_key",
    "api-key",
    "api_key",
    "sensitive",
}


def _text(*values: Any) -> str:
    """Convert multiple values into one lowercase text string."""
    return " ".join(str(value or "").lower() for value in values)


def _risk_level(score: int) -> str:
    """Convert the prototype score into a risk level."""
    if score >= 80:
        return "High"

    if score >= 60:
        return "Medium"

    if score >= 30:
        return "Low"

    return "Normal"


def _is_sensitive(event: Dict[str, Any]) -> bool:
    """Check whether an event involves a potentially sensitive resource."""

    tool = str(event.get("tool", "")).lower()

    text = _text(
        event.get("action"),
        event.get("target"),
        event.get("source"),
    )

    if tool in SENSITIVE_TOOL_KEYWORDS:
        return True

    return any(
        keyword in text
        for keyword in SENSITIVE_TEXT_KEYWORDS
    )


def fallback_analyze_sequence(
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Local fallback detector.

    This allows Member 3's AWS backend to remain independently
    testable if Member 2's Detection Engine is not deployed yet.

    The final project Detection Engine is owned by Member 2.
    """

    if not events:
        return {
            "risk_level": "Normal",
            "risk_score": 0,
            "status": "Normal",
            "reason_codes": [],
            "reasons": [],
            "attack_chain": [],
            "event_ids": [],
        }

    # Make sure events are processed chronologically.
    ordered = sorted(
        events,
        key=lambda event: (
            event.get("timestamp", ""),
            event.get("event_id", ""),
        ),
    )

    score = 0

    reason_codes: List[str] = []
    reasons: List[str] = []
    attack_chain: List[str] = []

    task = str(
        ordered[-1].get("task", "")
    ).lower()

    # ---------------------------------------------------------
    # RULE 1 — Unexpected tool
    # ---------------------------------------------------------

    unexpected_events = [
        event
        for event in ordered
        if str(event.get("tool", "")).lower()
        not in EXPECTED_TOOLS
    ]

    if unexpected_events:
        score += 20

        reason_codes.append(
            "UNEXPECTED_TOOL"
        )

        reasons.append(
            "The agent used a tool outside the expected "
            "email/document workflow."
        )

    # ---------------------------------------------------------
    # RULE 2 — Sensitive resource
    # ---------------------------------------------------------

    sensitive_events = [
        event
        for event in ordered
        if _is_sensitive(event)
    ]

    if sensitive_events:
        score += 30

        reason_codes.append(
            "SENSITIVE_RESOURCE"
        )

        reasons.append(
            "The sequence includes access to a potentially "
            "sensitive resource or action."
        )

    # ---------------------------------------------------------
    # RULE 3 — Cross-system movement
    # ---------------------------------------------------------

    tools = [
        str(event.get("tool", "")).lower()
        for event in ordered
    ]

    unique_tools = set(tools)

    if len(unique_tools) >= 3:
        score += 20

        reason_codes.append(
            "CROSS_SYSTEM_MOVEMENT"
        )

        reasons.append(
            "The agent moved across multiple systems/tools "
            "in one task sequence."
        )

    # ---------------------------------------------------------
    # RULE 4 — Task/action mismatch
    # ---------------------------------------------------------

    if task == "summarize_email" and unexpected_events:

        score += 30

        reason_codes.append(
            "TASK_ACTION_MISMATCH"
        )

        reasons.append(
            "Observed actions do not match the intended "
            "email-summary task."
        )

    # ---------------------------------------------------------
    # RULE 5 — Repeated unusual behaviour
    # ---------------------------------------------------------

    tool_counts = Counter(tools)

    unusual_count = len(unexpected_events)

    repeated_unusual = (
        unusual_count >= 2
        or any(
            count >= 2
            for tool, count in tool_counts.items()
            if tool not in EXPECTED_TOOLS
        )
    )

    if repeated_unusual:

        score += 20

        reason_codes.append(
            "REPEATED_UNUSUAL_BEHAVIOR"
        )

        reasons.append(
            "Multiple unusual actions occurred in "
            "the same sequence."
        )

    # Maximum prototype score = 100.
    score = min(score, 100)

    # ---------------------------------------------------------
    # ATTACK CHAIN
    # ---------------------------------------------------------

    for event in ordered:

        tool = str(
            event.get("tool", "")
        )

        target = str(
            event.get("target", "")
        )

        if target:
            attack_chain.append(
                f"{tool}:{target}"
            )
        else:
            attack_chain.append(tool)

    return {
        "risk_level": _risk_level(score),

        "risk_score": score,

        # We deliberately don't call it a confirmed attack.
        "status": (
            "Potentially Suspicious"
            if reason_codes
            else "Normal"
        ),

        "reason_codes": reason_codes,

        "reasons": reasons,

        "attack_chain": attack_chain,

        "event_ids": [
            event.get("event_id")
            for event in ordered
        ],
    }


def analyze_sequence(
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Analyze an event sequence.

    If Member 2's Detection Engine URL is configured,
    use it.

    Otherwise use the local fallback detector.

    This makes Member 3 independently testable.
    """

    detection_engine_url = os.getenv(
        "DETECTION_ENGINE_URL",
        ""
    ).strip()

    # ---------------------------------------------------------
    # If Member 2's detector isn't available,
    # use our local fallback.
    # ---------------------------------------------------------

    if not detection_engine_url:
        return fallback_analyze_sequence(events)

    payload = json.dumps(
        {
            "events": events
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        detection_engine_url,
        data=payload,
        headers={
            "Content-Type": "application/json"
        },
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=5,
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

            if not isinstance(result, dict):
                raise ValueError(
                    "Detection engine returned "
                    "an invalid response."
                )

            return result

    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError,
    ):

        # If Member 2's service is temporarily unavailable,
        # keep our backend operational.
        return fallback_analyze_sequence(events)