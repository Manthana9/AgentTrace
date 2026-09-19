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
        print(f"  [logger] {_GREEN}-> wrote to {config.LOG_FILE_PATH}{_RESET}")
    else:
        raise ValueError(f"Unknown config.MODE: {config.MODE!r}")

    print(f"  [logger]    {json.dumps(event)}")
    return event


def _send_http_with_fallback(event):
    if requests is None:
        print(f"  [logger] {_RED}requests not installed -- falling back to file{_RESET}")
        _write_to_file(event, config.FALLBACK_LOG_FILE_PATH)
        return

    last_error = None
    for attempt in range(1, config.HTTP_MAX_RETRIES + 2):
        try:
            resp = requests.post(
                config.DETECTION_ENGINE_URL,
                json=event,
                timeout=config.HTTP_TIMEOUT_SECONDS,
            )
            print(f"  [logger] {_GREEN}-> HTTP POST {config.DETECTION_ENGINE_URL} :: {resp.status_code}{_RESET}")
            return
        except Exception as exc:
            last_error = exc
            if attempt <= config.HTTP_MAX_RETRIES:
                print(f"  [logger] {_YELLOW}attempt {attempt} failed ({exc}), retrying...{_RESET}")
                time.sleep(config.HTTP_RETRY_BACKOFF_SECONDS)

    print(f"  [logger] {_RED}HTTP failed after retries ({last_error}){_RESET}")
    if config.FALLBACK_TO_FILE_ON_HTTP_FAILURE:
        _write_to_file(event, config.FALLBACK_LOG_FILE_PATH)
        print(f"  [logger] {_YELLOW}-> fell back to {config.FALLBACK_LOG_FILE_PATH}{_RESET}")


def _write_to_file(event, path):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def think(seconds=None):
    time.sleep(config.THINK_PAUSE_SECONDS if seconds is None else seconds)