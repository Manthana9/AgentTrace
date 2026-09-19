import json
import time
import uuid
from datetime import datetime, timezone

import config

if config.MODE == "http" or config.FALLBACK_TO_FILE_ON_HTTP_FAILURE:
    try:
        import requests
    except ImportError:
        requests = None

_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_RESET = "\033[0m"


def _build_event(task, tool, action, target, source):
    return {
        "event_id": f"evt_{uuid.uuid4().hex[:8]}",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent_id": config.AGENT_ID,
        "task": task,
        "tool": tool,
        "action": action,
        "target": target,
        "source": source,
    }


def log_event(task, tool, action, target, source):
    event = _build_event(task, tool, action, target, source)

    if config.MODE == "http":
        _send_http_with_fallback(event)

    elif config.MODE == "file":
        _write_to_file(event, config.LOG_FILE_PATH)
        print(
            f"  [logger] "
            f"{_GREEN}-> wrote to {config.LOG_FILE_PATH}{_RESET}"
        )

    else:
        raise ValueError(f"Unknown config.MODE: {config.MODE!r}")

    print(f"  [logger]    {json.dumps(event)}")

    return event


def _send_http_with_fallback(event):
    if requests is None:
        print(
            f"  [logger] "
            f"{_RED}requests not installed -- falling back to file{_RESET}"
        )

        _write_to_file(
            event,
            config.FALLBACK_LOG_FILE_PATH
        )

        return

    last_error = None

    for attempt in range(1, config.HTTP_MAX_RETRIES + 2):

        try:
            # Send event to AgentTrace Detection API
            resp = requests.post(
                config.DETECTION_ENGINE_URL,
                json=event,
                timeout=config.HTTP_TIMEOUT_SECONDS,
            )

            print(
                f"  [logger] "
                f"{_GREEN}-> HTTP POST "
                f"{config.DETECTION_ENGINE_URL} "
                f":: {resp.status_code}{_RESET}"
            )

            # ---------------------------------------------------------
            # Read detection result returned by AgentTrace
            # ---------------------------------------------------------

            if resp.ok:
                try:
                    result = resp.json()

                    detection = result.get("detection", {})

                    risk_level = detection.get(
                        "risk_level",
                        "UNKNOWN"
                    )

                    risk_score = detection.get(
                        "risk_score",
                        0
                    )

                    reasons = detection.get(
                        "reasons",
                        []
                    )

                    attack_chain = detection.get(
                        "attack_chain",
                        []
                    )

                    # NORMAL
                    if risk_level == "NORMAL":

                        print(
                            f"  [AgentTrace] "
                            f"{_GREEN}✓ NORMAL "
                            f"| Score: {risk_score}{_RESET}"
                        )

                    # LOW
                    elif risk_level == "LOW":

                        print(
                            f"  [AgentTrace] "
                            f"{_YELLOW}⚠ LOW RISK "
                            f"| Score: {risk_score}{_RESET}"
                        )

                        if reasons:
                            print(
                                f"  [AgentTrace] "
                                f"Reasons: {', '.join(reasons)}"
                            )

                    # MEDIUM
                    elif risk_level == "MEDIUM":

                        print(
                            f"  [AgentTrace] "
                            f"{_YELLOW}⚠ MEDIUM RISK "
                            f"| Score: {risk_score}{_RESET}"
                        )

                        if reasons:
                            print(
                                f"  [AgentTrace] "
                                f"Reasons: {', '.join(reasons)}"
                            )

                    # HIGH
                    elif risk_level == "HIGH":

                        print()
                        print(
                            f"  [AgentTrace] "
                            f"{_RED}🚨 HIGH RISK DETECTED "
                            f"| Score: {risk_score}{_RESET}"
                        )

                        if reasons:
                            print(
                                f"  [AgentTrace] "
                                f"{_RED}Reasons: "
                                f"{', '.join(reasons)}{_RESET}"
                            )

                        if attack_chain:
                            print(
                                f"  [AgentTrace] "
                                f"Attack Chain: "
                                f"{' -> '.join(attack_chain)}"
                            )

                        print()

                    # UNKNOWN
                    else:

                        print(
                            f"  [AgentTrace] "
                            f"Risk: {risk_level} "
                            f"| Score: {risk_score}"
                        )

                except ValueError:
                    print(
                        f"  [AgentTrace] "
                        f"{_YELLOW}"
                        f"Could not parse detection response."
                        f"{_RESET}"
                    )

            return

        except Exception as exc:

            last_error = exc

            if attempt <= config.HTTP_MAX_RETRIES:

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

    # -------------------------------------------------------------
    # HTTP failed completely
    # -------------------------------------------------------------

    print(
        f"  [logger] "
        f"{_RED}"
        f"HTTP failed after retries ({last_error})"
        f"{_RESET}"
    )

    if config.FALLBACK_TO_FILE_ON_HTTP_FAILURE:

        _write_to_file(
            event,
            config.FALLBACK_LOG_FILE_PATH
        )

        print(
            f"  [logger] "
            f"{_YELLOW}"
            f"-> fell back to "
            f"{config.FALLBACK_LOG_FILE_PATH}"
            f"{_RESET}"
        )


def _write_to_file(event, path):
    with open(path, "a", encoding="utf-8") as f:
        f.write(
            json.dumps(event) + "\n"
        )


def think(seconds=None):
    time.sleep(
        config.THINK_PAUSE_SECONDS
        if seconds is None
        else seconds
    )