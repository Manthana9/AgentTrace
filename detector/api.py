# detector/api.py

"""
AgentTrace Detection API

Local FastAPI interface for:
    - analyzing complete event sequences
    - receiving agent events in real time
    - maintaining temporary agent history
    - resetting an agent's demo history

The production AWS deployment uses the same detection concepts
behind API Gateway + Lambda.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional


from .detection_engine import analyze_events


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="AgentTrace Detection API",
    description=(
        "Detects suspicious AI-agent behavior and "
        "Living-Off-the-Agent activity."
    ),
    version="1.0.0",
)


# ============================================================
# EVENT MODEL
# ============================================================

class Event(BaseModel):

    event_id: str

    timestamp: Optional[str] = None

    agent_id: str

    task: str

    tool: str

    action: str

    target: str

    source: str


# ============================================================
# ANALYZE REQUEST
# ============================================================

class AnalyzeRequest(BaseModel):

    events: List[Event]


# ============================================================
# TEMPORARY EVENT STORE
# ============================================================

# Used only by the local development/demo API.
#
# Production:
#
#     API Gateway
#          ↓
#     Lambda
#          ↓
#     DynamoDB
#
event_history = {}


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "service": "AgentTrace Detection API",
        "status": "running",
        "version": "1.0.0",
    }


# ============================================================
# ANALYZE COMPLETE SEQUENCE
# ============================================================

@app.post("/analyze")
def analyze(request: AnalyzeRequest):

    events = [
        event.model_dump()
        for event in request.events
    ]

    result = analyze_events(events)

    return result


# ============================================================
# RECEIVE SINGLE EVENT
# ============================================================

@app.post("/event")
def receive_event(event: Event):
    """
    Receive one agent event, add it to the agent's temporary
    history, and analyze the complete sequence observed so far.
    """

    agent_id = event.agent_id

    # --------------------------------------------------------
    # Create history for a new agent
    # --------------------------------------------------------

    if agent_id not in event_history:
        event_history[agent_id] = []

    # --------------------------------------------------------
    # Store event
    # --------------------------------------------------------

    event_data = event.model_dump()

    event_history[agent_id].append(event_data)

    # --------------------------------------------------------
    # Analyze complete agent history
    # --------------------------------------------------------

    events = event_history[agent_id]

    result = analyze_events(events)

    # --------------------------------------------------------
    # Determine incident status
    # --------------------------------------------------------

    risk_score = result.get(
        "risk_score",
        0,
    )

    risk_level = result.get(
        "risk_level",
        "NORMAL",
    )

    is_suspicious = risk_level in {
        "MEDIUM",
        "HIGH",
    }

    # --------------------------------------------------------
    # Return response
    # --------------------------------------------------------

    return {
        "event_received": True,

        "event_id": event.event_id,

        "agent_id": agent_id,

        "detection": result,

        "incident": {
            "status": (
                "SUSPICIOUS"
                if is_suspicious
                else "NORMAL"
            ),

            "agent_id": agent_id,

            "task": result.get(
                "task"
            ),

            "risk_level": risk_level,

            "risk_score": risk_score,

            "expected_workflow": result.get(
                "expected_workflow",
                [],
            ),

            "observed_workflow": result.get(
                "observed_workflow",
                [],
            ),

            "attack_chain": result.get(
                "attack_chain",
                [],
            ),

            "reasons": result.get(
                "reasons",
                [],
            ),

            "reason_codes": result.get(
                "reason_codes",
                [],
            ),

            "evidence": result.get(
                "evidence",
                [],
            ),
        },
    }


# ============================================================
# RESET AGENT
# ============================================================

@app.post("/reset/{agent_id}")
def reset_agent(agent_id: str):
    """
    Clear temporary event history for an agent.

    Useful when starting a fresh local demo.
    """

    event_history.pop(
        agent_id,
        None,
    )

    return {
        "agent_id": agent_id,
        "status": "reset",
    }