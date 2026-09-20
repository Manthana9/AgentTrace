"""
AgentTrace - Event Logger

Responsible for:

1. Building structured agent activity events.
2. Sending events to the AgentTrace AWS detection API.
3. Displaying detection results in the terminal.
4. Falling back to a local file if the HTTP backend is unavailable.

Every event contains:

    agent_id
    timestamp
    task
    tool
    action
    target
    source

The logger does not decide whether activity is malicious.
That decision belongs to the AgentTrace detection engine.
"""

import json
import time
import uuid
from datetime import datetime, timezone

import config


# ============================================================
# OPTIONAL HTTP DEPENDENCY
# ============================================================

if (
    config.MODE == "http"
    or config.FALLBACK_TO_FILE_ON_HTTP_FAILURE
):
    try:
        import requests
    except ImportError:
        requests = None
else:
    requests = None


# ============================================================
# TERMINAL COLORS
# ============================================================

_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_RESET = "\033[0m"


# ============================================================
# EVENT CREATION
# ============================================================

def _build_event(
    task,
    tool,
    action,
    target,
    source,
    agent_id=None,
):
    """
    Build the structured event sent to AgentTrace.

    The task is intentionally preserved exactly as supplied
    by the agent.

    The agent_id can be supplied by ResearchAgent so that
    every execution gets its own isolated session/history.

    If no agent_id is supplied, the configured default
    config.AGENT_ID is used.
    """

    resolved_agent_id = agent_id or config.AGENT_ID

    return {
        "event_id": (
            f"evt_{uuid.uuid4().hex[:8]}"
        ),
        "timestamp": (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
        ),
        "agent_id": resolved_agent_id,
        "task": task,
        "tool": tool,
        "action": action,
        "target": target,
        "source": source,
    }


# ============================================================
# PUBLIC LOGGER
# ============================================================

def log_event(
    task,
    tool,
    action,
    target,
    source,
    agent_id=None,
):
    """
    Create and send one agent activity event.

    Depending on config.MODE:

        http
            Send to the AWS detection backend.

        file
            Write directly to the local log file.

    agent_id:
        Optional execution/session identifier.

        If supplied, it is preserved in the event.
        Otherwise config.AGENT_ID is used.
    """

    event = _build_event(
        task=task,
        tool=tool,
        action=action,
        target=target,
        source=source,
        agent_id=agent_id,
    )

    # --------------------------------------------------------
    # HTTP MODE
    # --------------------------------------------------------

    if config.MODE == "http":

        _send_http_with_fallback(event)

    # --------------------------------------------------------
    # FILE MODE
    # --------------------------------------------------------

    elif config.MODE == "file":

        _write_to_file(
            event,
            config.LOG_FILE_PATH,
        )

        print(
            f"  [logger] "
            f"{_GREEN}"
            f"-> wrote to "
            f"{config.LOG_FILE_PATH}"
            f"{_RESET}"
        )

    else:

        raise ValueError(
            f"Unknown config.MODE: "
            f"{config.MODE!r}"
        )

    # Always display the structured event locally.
    print(
        f"  [logger]    "
        f"{json.dumps(event)}"
    )

    return event


# ============================================================
# SEND EVENT TO AWS
# ============================================================

def _send_http_with_fallback(event):
    """
    Send an event to the AgentTrace AWS API.

    If the request fails after retries, optionally fall back
    to a local file.
    """

    if requests is None:

        print(
            f"  [logger] "
            f"{_RED}"
            f"requests not installed -- "
            f"falling back to file"
            f"{_RESET}"
        )

        _write_to_file(
            event,
            config.FALLBACK_LOG_FILE_PATH,
        )

        return

    last_error = None

    # --------------------------------------------------------
    # RETRIES
    # --------------------------------------------------------

    for attempt in range(
        1,
        config.HTTP_MAX_RETRIES + 2,
    ):

        try:

            response = requests.post(
                config.DETECTION_ENGINE_URL,
                json=event,
                timeout=(
                    config.HTTP_TIMEOUT_SECONDS
                ),
            )

            print(
                f"  [logger] "
                f"{_GREEN}"
                f"-> HTTP POST "
                f"{config.DETECTION_ENGINE_URL} "
                f":: {response.status_code}"
                f"{_RESET}"
            )

            # ------------------------------------------------
            # PROCESS DETECTION RESULT
            # ------------------------------------------------

            if response.ok:

                _display_detection_result(
                    response
                )

            else:

                print(
                    f"  [AgentTrace] "
                    f"{_YELLOW}"
                    f"Backend returned HTTP "
                    f"{response.status_code}"
                    f"{_RESET}"
                )

            return

        except Exception as exc:

            last_error = exc

            if (
                attempt
                <= config.HTTP_MAX_RETRIES
            ):

                print(
                    f"  [logger] "
                    f"{_YELLOW}"
                    f"attempt {attempt} failed "
                    f"({exc}), retrying..."
                    f"{_RESET}"
                )

                time.sleep(
                    config.HTTP_RETRY_BACKOFF_SECONDS
                )

    # --------------------------------------------------------
    # ALL HTTP ATTEMPTS FAILED
    # --------------------------------------------------------

    print(
        f"  [logger] "
        f"{_RED}"
        f"HTTP failed after retries "
        f"({last_error})"
        f"{_RESET}"
    )

    if config.FALLBACK_TO_FILE_ON_HTTP_FAILURE:

        _write_to_file(
            event,
            config.FALLBACK_LOG_FILE_PATH,
        )

        print(
            f"  [logger] "
            f"{_YELLOW}"
            f"-> fell back to "
            f"{config.FALLBACK_LOG_FILE_PATH}"
            f"{_RESET}"
        )


# ============================================================
# DETECTION RESULT DISPLAY
# ============================================================

def _display_detection_result(response):
    """
    Parse and display the detection result returned by
    the AgentTrace backend.

    The logger only displays the result.

    Detection decisions are made by the backend engine.
    """

    try:

        result = response.json()

    except ValueError:

        print(
            f"  [AgentTrace] "
            f"{_YELLOW}"
            f"Could not parse detection response."
            f"{_RESET}"
        )

        return

    detection = result.get(
        "detection",
        {},
    )

    if not detection:

        print(
            f"  [AgentTrace] "
            f"{_YELLOW}"
            f"No detection result returned."
            f"{_RESET}"
        )

        return

    # --------------------------------------------------------
    # Detection fields
    # --------------------------------------------------------

    risk_level = str(
        detection.get(
            "risk_level",
            "UNKNOWN",
        )
    ).upper()

    risk_score = detection.get(
        "risk_score",
        0,
    )

    status = detection.get(
        "status",
        "",
    )

    reasons = detection.get(
        "reasons",
        [],
    )

    reason_codes = detection.get(
        "reason_codes",
        [],
    )

    attack_chain = detection.get(
        "attack_chain",
        [],
    )

    # --------------------------------------------------------
    # NORMAL
    # --------------------------------------------------------

    if risk_level == "NORMAL":

        print(
            f"  [AgentTrace] "
            f"{_GREEN}"
            f"✓ NORMAL "
            f"| Score: {risk_score}"
            f"{_RESET}"
        )

        return

    # --------------------------------------------------------
    # LOW
    # --------------------------------------------------------

    if risk_level == "LOW":

        print(
            f"  [AgentTrace] "
            f"{_YELLOW}"
            f"⚠ LOW RISK "
            f"| Score: {risk_score}"
            f"{_RESET}"
        )

        _display_reasons(
            reasons,
            reason_codes,
        )

        return

    # --------------------------------------------------------
    # MEDIUM
    # --------------------------------------------------------

    if risk_level == "MEDIUM":

        print(
            f"  [AgentTrace] "
            f"{_YELLOW}"
            f"⚠ MEDIUM RISK "
            f"| Score: {risk_score}"
            f"{_RESET}"
        )

        _display_reasons(
            reasons,
            reason_codes,
        )

        return

    # --------------------------------------------------------
    # HIGH
    # --------------------------------------------------------

    if risk_level == "HIGH":

        print()

        print(
            f"  [AgentTrace] "
            f"{_RED}"
            f"🚨 HIGH RISK DETECTED "
            f"| Score: {risk_score}"
            f"{_RESET}"
        )

        if status:

            print(
                f"  [AgentTrace] "
                f"Status: {status}"
            )

        _display_reasons(
            reasons,
            reason_codes,
            color=_RED,
        )

        if attack_chain:

            if isinstance(
                attack_chain,
                list,
            ):

                print(
                    f"  [AgentTrace] "
                    f"Attack Chain: "
                    f"{' -> '.join(attack_chain)}"
                )

            else:

                print(
                    f"  [AgentTrace] "
                    f"Attack Chain: "
                    f"{attack_chain}"
                )

        print()

        return

    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    print(
        f"  [AgentTrace] "
        f"Risk: {risk_level} "
        f"| Score: {risk_score}"
    )

    _display_reasons(
        reasons,
        reason_codes,
    )


# ============================================================
# DETECTION REASONS
# ============================================================

def _display_reasons(
    reasons,
    reason_codes,
    color=_YELLOW,
):
    """
    Display human-readable detection reasons and
    their corresponding rule codes.
    """

    if reason_codes:

        print(
            f"  [AgentTrace] "
            f"Reason codes: "
            f"{', '.join(reason_codes)}"
        )

    if reasons:

        print(
            f"  [AgentTrace] "
            f"{color}"
            f"Reasons:"
            f"{_RESET}"
        )

        for reason in reasons:

            print(
                f"      • {reason}"
            )


# ============================================================
# LOCAL FILE LOGGING
# ============================================================

def _write_to_file(
    event,
    path,
):
    """
    Append one JSON event to a local log file.
    """

    with open(
        path,
        "a",
        encoding="utf-8",
    ) as file:

        file.write(
            json.dumps(event)
            + "\n"
        )


# ============================================================
# AGENT THINKING PAUSE
# ============================================================

def think(seconds=None):
    """
    Simulate the agent thinking between tool calls.
    """

    time.sleep(
        config.THINK_PAUSE_SECONDS
        if seconds is None
        else seconds
    )