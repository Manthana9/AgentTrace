from __future__ import annotations

import os
from typing import Any, Dict, List

import boto3
from boto3.dynamodb.conditions import Key


class DynamoDBService:
    """
    Handles AgentTrace DynamoDB operations.

    LOCAL MODE:
        Used for development/testing without AWS.

    AWS MODE:
        Uses real Amazon DynamoDB tables.
    """

    # Used only when AGENTTRACE_LOCAL_MODE=true.
    _local_events: List[Dict[str, Any]] = []

    _local_incidents: List[
        Dict[str, Any]
    ] = []

    def __init__(self) -> None:

        self.local_mode = (
            os.getenv(
                "AGENTTRACE_LOCAL_MODE",
                "false",
            ).lower()
            == "true"
        )

        self.events_table_name = os.getenv(
            "EVENTS_TABLE_NAME",
            "AgentTraceEvents",
        )

        self.incidents_table_name = os.getenv(
            "INCIDENTS_TABLE_NAME",
            "AgentTraceIncidents",
        )

        self._events_table = None
        self._incidents_table = None

        # -----------------------------------------------------
        # AWS MODE
        # -----------------------------------------------------

        if not self.local_mode:

            dynamodb = boto3.resource(
                "dynamodb"
            )

            self._events_table = dynamodb.Table(
                self.events_table_name
            )

            self._incidents_table = dynamodb.Table(
                self.incidents_table_name
            )

    # ---------------------------------------------------------
    # STORE EVENT
    # ---------------------------------------------------------
    def put_event(
        self,
        event: Dict[str, Any],
    ) -> None:

        if self.local_mode:

            event_id = event.get("event_id")

            for index, existing_event in enumerate(self._local_events):

                if existing_event.get("event_id") == event_id:
                    self._local_events[index] = dict(event)
                    return

            self._local_events.append(
                dict(event)
            )

            return

        self._events_table.put_item(
            Item=event
        )

    # ---------------------------------------------------------
    # GET EVENTS FOR AGENT
    # ---------------------------------------------------------

    def get_events(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:

        if self.local_mode:

            events = [
                event
                for event in self._local_events
                if event.get("agent_id")
                == agent_id
            ]

            events.sort(
                key=lambda event: (
                    event.get(
                        "timestamp",
                        "",
                    ),
                    event.get(
                        "event_id",
                        "",
                    ),
                )
            )

            return events[-limit:]

        response = self._events_table.query(

            KeyConditionExpression=Key(
                "agent_id"
            ).eq(agent_id),

            # Get newest events first from DynamoDB.
            ScanIndexForward=False,

            Limit=limit,
        )

        events = response.get(
            "Items",
            [],
        )

        # Return chronological order.
        events.reverse()

        return events

    # ---------------------------------------------------------
    # STORE INCIDENT
    # ---------------------------------------------------------

    def put_incident(
        self,
        incident: Dict[str, Any],
    ) -> None:

        if self.local_mode:

            self._local_incidents.append(
                dict(incident)
            )

            return

        self._incidents_table.put_item(
            Item=incident
        )