from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone
import boto3

from typing import Any, Dict


from detection_service import analyze_sequence
from dynamodb_service import DynamoDBService

BEDROCK_MODEL_ID = "eu.amazon.nova-lite-v1:0"

bedrock = boto3.client(
    "bedrock-runtime",
    region_name=os.environ.get(
        "AWS_REGION",
        "eu-north-1",
    ),
)

def generate_bedrock_explanation(
    detection: Dict[str, Any],
    events: list[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Generate a human-readable security explanation using
    Amazon Bedrock.

    If Bedrock is unavailable or the Lambda execution role
    does not have permission, detection continues normally.
    """

    prompt = f"""
You are a cybersecurity analyst assisting a security
monitoring system called AgentTrace.

AgentTrace detects potentially suspicious behavior where
an AI agent may be manipulated into abusing its legitimate
tools and permissions.

Analyze the following detection evidence.

Detection:
- Risk level: {detection.get("risk_level")}
- Risk score: {detection.get("risk_score")}
- Status: {detection.get("status")}
- Reason codes: {detection.get("reason_codes", [])}
- Reasons: {detection.get("reasons", [])}
- Attack chain: {" -> ".join(detection.get("attack_chain", []))}

Recent agent events:
{json.dumps(events[-10:], indent=2, default=str)}

Explain the activity for a security analyst.

Return ONLY valid JSON using exactly this structure:

{{
    "title": "Short incident title",
    "explanation": "A concise 2-4 sentence explanation of what happened.",
    "why_suspicious": [
        "Reason 1",
        "Reason 2"
    ],
    "attack_chain": "tool1 -> tool2 -> tool3",
    "response": [
        "Recommended response 1",
        "Recommended response 2",
        "Recommended response 3"
    ]
}}

Important:
- Do not invent evidence.
- Use only the supplied detection and event data.
- Do not claim that an attack is confirmed.
- Describe it as potentially suspicious activity.
"""

    try:
        response = bedrock.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "text": prompt,
                        }
                    ],
                }
            ],
            inferenceConfig={
                "maxTokens": 500,
                "temperature": 0.2,
            },
        )

        text = (
            response["output"]
            ["message"]
            ["content"][0]
            ["text"]
        ).strip()

        if text.startswith("```json"):
            text = text[7:]

        if text.startswith("```"):
            text = text[3:]

        if text.endswith("```"):
            text = text[:-3]

        text = text.strip()

        explanation = json.loads(text)

        return {
            "status": "ready",
            "provider": "Amazon Bedrock",
            "model": BEDROCK_MODEL_ID,
            "title": explanation.get(
                "title",
                "AI Security Analysis",
            ),
            "explanation": explanation.get(
                "explanation",
                "",
            ),
            "why_suspicious": explanation.get(
                "why_suspicious",
                [],
            ),
            "attack_chain": explanation.get(
                "attack_chain",
                "",
            ),
            "response": explanation.get(
                "response",
                [],
            ),
        }

    except Exception as exc:
        logger.warning(
            "Bedrock explanation unavailable: %s",
            exc,
        )

        return {
            "status": "unavailable",
            "provider": "Amazon Bedrock",
            "model": BEDROCK_MODEL_ID,
            "error": str(exc),
        }



# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger()

logger.setLevel(
    logging.INFO
)


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
# API RESPONSE
# ============================================================

def _response(
    status_code: int,
    body: Dict[str, Any],
) -> Dict[str, Any]:

    return {

        "statusCode": status_code,

        "headers": {

            "Content-Type":
                "application/json",

            "Access-Control-Allow-Origin":
                "*",

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

    body = event.get(
        "body"
    )

    # Direct Lambda invocation.
    if body is None:
        return event

    # Already decoded JSON object.
    if isinstance(
        body,
        dict,
    ):
        return body

    if not isinstance(
        body,
        str,
    ):
        raise ValueError(
            "Request body must be a JSON object."
        )

    # Handle Base64 encoded API Gateway requests.
    if event.get(
        "isBase64Encoded"
    ) is True:

        body = base64.b64decode(
            body
        ).decode(
            "utf-8"
        )

    parsed = json.loads(
        body
    )

    if not isinstance(
        parsed,
        dict,
    ):
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
    # Check required fields
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
    # Check field values
    # --------------------------------------------------------

    for field in REQUIRED_FIELDS:

        value = raw[field]

        if (
            not isinstance(
                value,
                str,
            )
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
    # Generate unique event ID
    # --------------------------------------------------------

    event_id = (
        raw.get("event_id")
        or str(uuid.uuid4())
    )

    timestamp_value = (
        raw["timestamp"].strip()
    )

    # --------------------------------------------------------
    # Final normalized event
    # --------------------------------------------------------

    event = {

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

        # DynamoDB sort key.
        "event_sort_key":
            f"{timestamp_value}#{event_id}",
    }

    return event


# ============================================================
# MAIN AWS LAMBDA HANDLER
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
        # 3. CONNECT DATABASE
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
        # 5. GET RECENT AGENT EVENTS
        # ====================================================

        events = db.get_events(
            agent_event["agent_id"],
            limit=100,
        )

        # ====================================================
        # 6. RUN DETECTION
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
            "Normal",
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
        # 7. UPDATE EVENT WITH CURRENT DETECTION STATE
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

        # Re-save event with detection state.
        db.put_event(
            agent_event
        )

        # ====================================================
        # 8. CREATE INCIDENT IF SUSPICIOUS
        # ====================================================

        incident = None
        ai_explanation = None

        if status == "Potentially Suspicious":

            incident = {
    "incident_id": str(uuid.uuid4()),

    "agent_id": agent_event["agent_id"],

    "created_at": datetime.now(
        timezone.utc
    ).isoformat(),

    "risk_status": status,

    "risk_level": risk_level,

    "risk_score": risk_score,

    "reason_codes": detection.get(
        "reason_codes",
        [],
    ),

    "reasons": detection.get(
        "reasons",
        [],
    ),

    "attack_chain": detection.get(
        "attack_chain",
        [],
    ),

    "expected_workflow": detection.get(
        "expected_workflow",
        [],
    ),

    "observed_workflow": detection.get(
        "observed_workflow",
        [],
    ),

    "evidence": detection.get(
        "evidence",
        [],
    ),

    "event_ids": detection.get(
        "event_ids",
        [],
    ),
}

            db.put_incident(
                incident
            )

            # Generate an AI security explanation with Amazon Bedrock.
            ai_explanation = generate_bedrock_explanation(
                detection,
                events,
            )

            logger.info(
                "Bedrock explanation status: %s",
                ai_explanation.get("status"),
            )

            logger.info(
                "Potential incident stored: %s",
                incident["incident_id"],
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

                "incident":
                    incident,

                "ai_explanation":
                    ai_explanation,
            },
        )

    # ========================================================
    # CLIENT VALIDATION ERROR
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
    # EVENT VALIDATION ERROR
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
    # UNEXPECTED SERVER ERROR
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