"""
AgentTrace - Configuration

Central configuration for the ResearchAgent simulator,
event logger, and AgentTrace detection backend.
"""

import os


# ============================================================
# OPTIONAL .ENV SUPPORT
# ============================================================

try:
    from dotenv import load_dotenv

    load_dotenv()

except ImportError:
    pass


# ============================================================
# LOGGING MODE
# ============================================================

# "http"  -> send events to the AWS AgentTrace backend
# "file"  -> write events locally
MODE = os.getenv(
    "AGENT_LOG_MODE",
    "http",
)


# ============================================================
# AWS DETECTION API
# ============================================================

DETECTION_ENGINE_URL = os.getenv(
    "AGENTTRACE_API_URL",
    "https://9gf9r8x4n5.execute-api.eu-north-1.amazonaws.com/dev/events",
)


# ============================================================
# LOCAL LOGGING
# ============================================================

LOG_FILE_PATH = os.getenv(
    "AGENT_LOG_FILE",
    "events.jsonl",
)


# ============================================================
# FALLBACK
# ============================================================

# If the AWS endpoint is temporarily unavailable,
# keep a local copy of the event rather than losing it.
FALLBACK_TO_FILE_ON_HTTP_FAILURE = True

FALLBACK_LOG_FILE_PATH = os.getenv(
    "AGENT_FALLBACK_LOG_FILE",
    "events_fallback.jsonl",
)


# ============================================================
# HTTP SETTINGS
# ============================================================

HTTP_TIMEOUT_SECONDS = float(
    os.getenv(
        "AGENT_HTTP_TIMEOUT",
        "2",
    )
)

HTTP_MAX_RETRIES = int(
    os.getenv(
        "AGENT_HTTP_RETRIES",
        "2",
    )
)

HTTP_RETRY_BACKOFF_SECONDS = float(
    os.getenv(
        "AGENT_HTTP_BACKOFF",
        "0.5",
    )
)


# ============================================================
# AGENT IDENTITY
# ============================================================

AGENT_ID = os.getenv(
    "AGENT_ID",
    "research-agent-01",
)


# ============================================================
# SIMULATION TIMING
# ============================================================

# Pause used by scenarios to simulate agent reasoning
# between tool calls.
THINK_PAUSE_SECONDS = float(
    os.getenv(
        "AGENT_THINK_PAUSE",
        "1",
    )
)