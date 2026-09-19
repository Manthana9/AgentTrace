import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

MODE = os.getenv("AGENT_LOG_MODE", "http")

DETECTION_ENGINE_URL = "http://10.170.174.73:8000/event"
LOG_FILE_PATH = os.getenv("AGENT_LOG_FILE", "events.jsonl")

FALLBACK_TO_FILE_ON_HTTP_FAILURE = True
FALLBACK_LOG_FILE_PATH = os.getenv("AGENT_FALLBACK_LOG_FILE", "events_fallback.jsonl")

HTTP_TIMEOUT_SECONDS = float(os.getenv("AGENT_HTTP_TIMEOUT", "2"))
HTTP_MAX_RETRIES = int(os.getenv("AGENT_HTTP_RETRIES", "2"))
HTTP_RETRY_BACKOFF_SECONDS = float(os.getenv("AGENT_HTTP_BACKOFF", "0.5"))

AGENT_ID = os.getenv("AGENT_ID", "research-agent-01")

THINK_PAUSE_SECONDS = float(os.getenv("AGENT_THINK_PAUSE", "1"))