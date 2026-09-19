from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any

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


@app.get("/")
def root():
    return {
        "service": "AgentTrace Detection API",
        "status": "running"
    }


@app.post("/analyze")
def analyze(request: AnalyzeRequest):

    # Convert Pydantic objects into dictionaries
    events = [
        event.model_dump()
        for event in request.events
    ]

    # Send events to our detection engine
    result = analyze_events(events)

    return result