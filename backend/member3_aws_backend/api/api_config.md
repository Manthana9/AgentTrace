# AgentTrace API

## Endpoint

POST /events

Purpose:

Receives structured AgentTrace activity events.

## Request

Content-Type:

application/json

Example:

{
  "agent_id": "research-agent-01",
  "timestamp": "2026-09-19T12:00:00Z",
  "task": "summarize_email",
  "tool": "email",
  "action": "read_email",
  "target": "project-inbox",
  "source": "user_task"
}

## Processing Flow

API Gateway
    ↓
AWS Lambda
    ↓
Validate Event
    ↓
DynamoDB
    ↓
Detection Engine
    ↓
Detection Result
    ↓
API Response

## Response

The API returns:

- Processed event
- Risk status
- Risk level
- Risk score
- Reason codes
- Reasons
- Attack chain
- Incident metadata when applicable