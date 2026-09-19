from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

from .detection_engine import analyze_events


app = FastAPI(
    title="AgentTrace Detection API",
    description="Detects suspicious AI-agent behavior and Living-Off-the-Agent activity.",
    version="1.0.0"
)


class Event(BaseModel):
    event_id: str
    timestamp: str | None = None
    agent_id: str
    task: str
    tool: str
    action: str
    target: str
    source: str


class AnalyzeRequest(BaseModel):
    events: List[Event]


# Temporary in-memory event store.
# Later this will be replaced with DynamoDB.
event_history = {}


@app.get("/")
def root():
    return {
        "service": "AgentTrace Detection API",
        "status": "running"
    }


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    events = [event.model_dump() for event in request.events]

    result = analyze_events(events)

    return result


@app.post("/event")
def receive_event(event: Event):
    """
    Receive one agent event in real time,
    store it temporarily, and analyze the
    agent's activity history.
    """

    agent_id = event.agent_id

    if agent_id not in event_history:
        event_history[agent_id] = []

    event_history[agent_id].append(event.model_dump())

    events = event_history[agent_id]

    result = analyze_events(events)

    is_suspicious = result.get("risk_level") in {
        "MEDIUM",
        "HIGH"
    }

    return {
        "event_received": True,
        "event_id": event.event_id,
        "agent_id": agent_id,
        "detection": result,
        "incident": {
            "status": "SUSPICIOUS" if is_suspicious else "NORMAL",
            "agent_id": agent_id,
            "risk_level": result.get("risk_level"),
            "risk_score": result.get("risk_score"),
            "attack_chain": result.get("attack_chain", []),
            "reasons": result.get("reasons", []),
            "evidence": result.get("evidence", [])
        }
    }


@app.post("/reset/{agent_id}")
def reset_agent(agent_id: str):
    """
    Clear the temporary event history for an agent.

    Used to start a fresh detection scenario.
    """

    event_history.pop(agent_id, None)

    return {
        "agent_id": agent_id,
        "status": "reset"
    }