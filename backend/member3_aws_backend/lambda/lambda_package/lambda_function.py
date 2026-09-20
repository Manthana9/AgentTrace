# lambda_function.py

from __future__ import annotations

import base64
import json
import logging
import os
import uuid

from datetime import datetime, timezone
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from detection_service import analyze_sequence
from dynamodb_service import DynamoDBService


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ============================================================
# REQUIRED EVENT FIELDS
# ============================================================

REQUIRED_FIELDS = (
    "agent_id",
    "timestamp",
    "task",
    "tool",
    "action",
    "target",
    "source",
)


# ============================================================
# AMAZON BEDROCK
# ============================================================

BEDROCK_REGION = os.environ.get(
    "BEDROCK_REGION",
    os.environ.get(
        "AWS_REGION",
        "eu-north-1",
    ),
)

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "eu.amazon.nova-lite-v1:0",
)


# ============================================================
# API RESPONSE
# ============================================================

def _response(
    status_code: int,
    body: Dict[str, Any],
) -> Dict[str, Any]:

    return {
        "statusCode": status_code,

        "headers": {
            "Content-Type": "application/json",

            "Access-Control-Allow-Origin": "*",

            "Access-Control-Allow-Headers":
                "Content-Type",

            "Access-Control-Allow-Methods":
                "POST,OPTIONS",
        },

        "body": json.dumps(
            body,
            default=str,
        ),
    }


# ============================================================
# PARSE API GATEWAY BODY
# ============================================================

def _parse_body(
    event: Dict[str, Any],
) -> Dict[str, Any]:

    body = event.get("body")

    # Direct Lambda invocation.
    if body is None:
        return event

    # Already decoded object.
    if isinstance(body, dict):
        return body

    if not isinstance(body, str):
        raise ValueError(
            "Request body must be a JSON object."
        )

    # API Gateway Base64 support.
    if event.get(
        "isBase64Encoded"
    ) is True:

        body = base64.b64decode(
            body
        ).decode("utf-8")

    parsed = json.loads(body)

    if not isinstance(parsed, dict):
        raise ValueError(
            "Request JSON must be an object."
        )

    return parsed


# ============================================================
# VALIDATE + NORMALIZE EVENT
# ============================================================

def _validate_and_normalize(
    raw: Dict[str, Any],
) -> Dict[str, Any]:

    # --------------------------------------------------------
    # Required fields
    # --------------------------------------------------------

    missing = [
        field
        for field in REQUIRED_FIELDS
        if field not in raw
    ]

    if missing:

        raise ValueError(
            "Missing required fields: "
            + ", ".join(missing)
        )

    # --------------------------------------------------------
    # Validate strings
    # --------------------------------------------------------

    for field in REQUIRED_FIELDS:

        value = raw[field]

        if (
            not isinstance(value, str)
            or not value.strip()
        ):

            raise ValueError(
                f"Field '{field}' "
                "must be a non-empty string."
            )

    # --------------------------------------------------------
    # Validate timestamp
    # --------------------------------------------------------

    timestamp = raw[
        "timestamp"
    ].replace(
        "Z",
        "+00:00",
    )

    try:

        datetime.fromisoformat(
            timestamp
        )

    except ValueError as exc:

        raise ValueError(
            "Field 'timestamp' must be "
            "a valid ISO-8601 timestamp."
        ) from exc

    # --------------------------------------------------------
    # Event ID
    # --------------------------------------------------------

    event_id = (
        raw.get("event_id")
        or str(uuid.uuid4())
    )

    timestamp_value = (
        raw["timestamp"].strip()
    )

    # --------------------------------------------------------
    # Normalized event
    # --------------------------------------------------------

    return {

        "event_id":
            event_id,

        "agent_id":
            raw["agent_id"].strip(),

        "timestamp":
            timestamp_value,

        "task":
            raw["task"].strip(),

        "tool":
            raw["tool"].strip(),

        "action":
            raw["action"].strip(),

        "target":
            raw["target"].strip(),

        "source":
            raw["source"].strip(),

        "received_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "event_sort_key":
            f"{timestamp_value}#{event_id}",
    }


# ============================================================
# BEDROCK EXPLANATION
# ============================================================

def _generate_bedrock_explanation(
    agent_event: Dict[str, Any],
    detection: Dict[str, Any],
    events: list[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Generate an explainable security analysis using Amazon
    Bedrock.

    Bedrock failure never invalidates the deterministic
    AgentTrace detection result.
    """

    bedrock = boto3.client(
        "bedrock-runtime",
        region_name=BEDROCK_REGION,
    )

    recent_events = [
        {
            "timestamp":
                item.get("timestamp"),

            "task":
                item.get("task"),

            "tool":
                item.get("tool"),

            "action":
                item.get("action"),

            "target":
                item.get("target"),

            "source":
                item.get("source"),
        }

        for item in events[-20:]
    ]

    evidence = {

        "agent_id":
            agent_event.get("agent_id"),

        "current_task":
            agent_event.get("task"),

        "risk_level":
            detection.get("risk_level"),

        "risk_score":
            detection.get("risk_score"),

        "reason_codes":
            detection.get(
                "reason_codes",
                [],
            ),

        "reasons":
            detection.get(
                "reasons",
                [],
            ),

        "expected_workflow":
            detection.get(
                "expected_workflow",
                [],
            ),

        "observed_workflow":
            detection.get(
                "observed_workflow",
                [],
            ),

        "attack_chain":
            detection.get(
                "attack_chain",
                [],
            ),

        "event_ids":
            detection.get(
                "event_ids",
                [],
            ),

        "recent_events":
            recent_events,
    }

    prompt = f"""
You are the security-analysis component of AgentTrace,
a prototype that detects Living-Off-the-Agent (LOTA) behavior.

Analyze ONLY the telemetry supplied below.

Do not claim that an attack is confirmed.
Describe the activity as potentially suspicious when
appropriate.

Do not invent missing facts.

Return a concise analyst report with exactly these
four sections:

1. Assessment
2. Why suspicious
3. Attack path
4. Recommended response

In Assessment:
State whether the telemetry is potentially suspicious
and summarize the main concern in 1-2 sentences.

In Why suspicious:
Explain the strongest evidence, especially:
- unexpected tool usage
- sensitive access
- untrusted-to-sensitive transitions
- cross-system movement
- deviation from the expected workflow

In Attack path:
Describe the observed tool sequence.

In Recommended response:
Give 3-5 practical defensive actions such as:
- validating the agent task
- reviewing affected credentials/sessions
- restricting suspicious tool access
- isolating the agent if necessary
- investigating referenced systems

Do not recommend offensive actions.

AgentTrace telemetry:

{json.dumps(
    evidence,
    indent=2,
    default=str,
)}
"""

    try:

        response = bedrock.converse(

            modelId=BEDROCK_MODEL_ID,

            messages=[
                {
                    "role": "user",

                    "content": [
                        {
                            "text": prompt
                        }
                    ],
                }
            ],

            inferenceConfig={
                "maxTokens": 600,
                "temperature": 0.2,
            },
        )

        content = (
            response
            .get("output", {})
            .get("message", {})
            .get("content", [])
        )

        text = next(
            (
                item.get("text")
                for item in content
                if item.get("text")
            ),
            None,
        )

        if not text:

            raise RuntimeError(
                "Bedrock returned no text content."
            )

        return {
            "status": "ready",

            "provider":
                "Amazon Bedrock",

            "model":
                BEDROCK_MODEL_ID,

            "explanation":
                text.strip(),
        }

    except ClientError as exc:

        error = exc.response.get(
            "Error",
            {},
        )

        code = error.get(
            "Code",
            "BedrockError",
        )

        logger.warning(
            "Bedrock unavailable: %s - %s",
            code,
            error.get(
                "Message",
                "Unknown Bedrock error",
            ),
        )

        return {
            "status": "unavailable",

            "provider":
                "Amazon Bedrock",

            "model":
                BEDROCK_MODEL_ID,

            "error_code":
                code,

            "message":
                (
                    "Bedrock explanation unavailable; "
                    "detection result is still valid."
                ),
        }

    except Exception as exc:

        logger.exception(
            "Unexpected Bedrock explanation error: %s",
            exc,
        )

        return {
            "status": "unavailable",

            "provider":
                "Amazon Bedrock",

            "model":
                BEDROCK_MODEL_ID,

            "error_code":
                type(exc).__name__,

            "message":
                (
                    "Bedrock explanation unavailable; "
                    "detection result is still valid."
                ),
        }


# ============================================================
# MAIN LAMBDA HANDLER
# ============================================================

def lambda_handler(
    event: Dict[str, Any],
    context: Any,
) -> Dict[str, Any]:

    logger.info(
        "AgentTrace event received."
    )

    # --------------------------------------------------------
    # CORS preflight
    # --------------------------------------------------------

    request_context = event.get(
        "requestContext",
        {},
    )

    http_info = request_context.get(
        "http",
        {},
    )

    if http_info.get(
        "method"
    ) == "OPTIONS":

        return _response(
            200,
            {
                "message": "OK"
            },
        )

    try:

        # ====================================================
        # 1. PARSE REQUEST
        # ====================================================

        raw_event = _parse_body(
            event
        )

        # ====================================================
        # 2. VALIDATE EVENT
        # ====================================================

        agent_event = (
            _validate_and_normalize(
                raw_event
            )
        )

        logger.info(
            "Validated event_id=%s agent_id=%s",
            agent_event["event_id"],
            agent_event["agent_id"],
        )

        # ====================================================
        # 3. CONNECT TO DATABASE
        # ====================================================

        db = DynamoDBService()

        # ====================================================
        # 4. STORE EVENT
        # ====================================================

        db.put_event(
            agent_event
        )

        logger.info(
            "Event stored successfully."
        )

        # ====================================================
        # 5. GET AGENT HISTORY
        # ====================================================

        events = db.get_events(
            agent_event["agent_id"],
            limit=100,
        )

        # ====================================================
        # 6. RUN DETERMINISTIC DETECTION
        # ====================================================

        detection = analyze_sequence(
            events
        )

        risk_score = int(
            detection.get(
                "risk_score",
                0,
            )
        )

        risk_level = detection.get(
            "risk_level",
            "NORMAL",
        )

        status = detection.get(
            "status",
            "Normal",
        )

        logger.info(
            "Detection completed: "
            "status=%s score=%s level=%s",
            status,
            risk_score,
            risk_level,
        )

        # ====================================================
        # 7. UPDATE EVENT WITH DETECTION STATE
        # ====================================================

        agent_event.update({

            "risk_status":
                status,

            "risk_level":
                risk_level,

            "risk_score":
                risk_score,

            "reason_codes":
                detection.get(
                    "reason_codes",
                    [],
                ),
        })

        db.put_event(
            agent_event
        )

        # ====================================================
        # 8. INCIDENT + AI EXPLANATION
        # ====================================================

        incident = None
        ai_explanation = None

        if status == "Potentially Suspicious":

            incident = {

                "incident_id":
                    str(uuid.uuid4()),

                "agent_id":
                    agent_event["agent_id"],

                "created_at":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),

                "risk_status":
                    status,

                "risk_level":
                    risk_level,

                "risk_score":
                    risk_score,

                "reason_codes":
                    detection.get(
                        "reason_codes",
                        [],
                    ),

                "reasons":
                    detection.get(
                        "reasons",
                        [],
                    ),

                "expected_workflow":
                    detection.get(
                        "expected_workflow",
                        [],
                    ),

                "observed_workflow":
                    detection.get(
                        "observed_workflow",
                        [],
                    ),

                "attack_chain":
                    detection.get(
                        "attack_chain",
                        [],
                    ),

                "event_ids":
                    detection.get(
                        "event_ids",
                        [],
                    ),

                "evidence":
                    detection.get(
                        "evidence",
                        [],
                    ),
            }

            # ------------------------------------------------
            # Store deterministic incident first
            # ------------------------------------------------

            db.put_incident(
                incident
            )

            logger.info(
                "Potential incident stored: %s",
                incident["incident_id"],
            )

            # ------------------------------------------------
            # Bedrock explanation
            # ------------------------------------------------

            ai_explanation = (
                _generate_bedrock_explanation(
                    agent_event,
                    detection,
                    events,
                )
            )

            incident[
                "ai_explanation"
            ] = ai_explanation

            # ------------------------------------------------
            # Persist enriched incident
            # ------------------------------------------------

            db.put_incident(
                incident
            )

            logger.info(
                "Bedrock explanation status: %s",
                ai_explanation.get(
                    "status"
                ),
            )

        # ====================================================
        # 9. RETURN RESULT
        # ====================================================

        return _response(

            200,

            {

                "message":
                    "AgentTrace event processed successfully.",

                "event":
                    agent_event,

                "detection":
                    detection,

                "ai_explanation":
                    ai_explanation,

                "incident":
                    incident,
            },
        )

    # ========================================================
    # INVALID JSON
    # ========================================================

    except json.JSONDecodeError:

        logger.exception(
            "Invalid JSON request."
        )

        return _response(
            400,
            {
                "error":
                    "Request body contains invalid JSON."
            },
        )

    # ========================================================
    # VALIDATION ERROR
    # ========================================================

    except ValueError as exc:

        logger.warning(
            "Validation error: %s",
            exc,
        )

        return _response(
            400,
            {
                "error":
                    str(exc)
            },
        )

    # ========================================================
    # UNEXPECTED ERROR
    # ========================================================

    except Exception:

        logger.exception(
            "Unhandled AgentTrace backend error."
        )

        return _response(
            500,
            {
                "error":
                    "Internal server error."
            },
        )