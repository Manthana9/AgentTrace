# dynamodb_service.py

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
        Uses Amazon DynamoDB.
    """

    # ========================================================
    # LOCAL DEVELOPMENT STORAGE
    # ========================================================

    _local_events: List[Dict[str, Any]] = []

    _local_incidents: List[Dict[str, Any]] = []

    # ========================================================
    # INITIALIZATION
    # ========================================================

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

        # ----------------------------------------------------
        # AWS MODE
        # ----------------------------------------------------

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

    # ========================================================
    # STORE EVENT
    # ========================================================

    def put_event(
        self,
        event: Dict[str, Any],
    ) -> None:

        if self.local_mode:

            event_id = event.get(
                "event_id"
            )

            # ----------------------------------------------
            # Replace an existing event with the same ID
            # ----------------------------------------------

            for index, existing_event in enumerate(
                self._local_events
            ):

                if (
                    existing_event.get("event_id")
                    == event_id
                ):

                    self._local_events[index] = dict(
                        event
                    )

                    return

            # ----------------------------------------------
            # Otherwise add a new event
            # ----------------------------------------------

            self._local_events.append(
                dict(event)
            )

            return

        # ----------------------------------------------------
        # AWS DynamoDB
        # ----------------------------------------------------

        self._events_table.put_item(
            Item=event
        )

    # ========================================================
    # GET EVENTS FOR AGENT
    # ========================================================

    def get_events(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Return the most recent events for one agent
        in chronological order.
        """

        if self.local_mode:

            events = [
                event
                for event in self._local_events
                if event.get("agent_id")
                == agent_id
            ]

            # ------------------------------------------------
            # Deterministic chronological ordering
            # ------------------------------------------------

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

        # ----------------------------------------------------
        # AWS DynamoDB
        # ----------------------------------------------------

        response = self._events_table.query(
            KeyConditionExpression=Key(
                "agent_id"
            ).eq(agent_id),

            # Newest records first from DynamoDB.
            ScanIndexForward=False,

            Limit=limit,
        )

        events = response.get(
            "Items",
            [],
        )

        # ----------------------------------------------------
        # Detection expects chronological order.
        # ----------------------------------------------------

        events.reverse()

        return events

    # ========================================================
    # STORE INCIDENT
    # ========================================================

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

    # ========================================================
    # CLEAR LOCAL DATA
    # ========================================================

    @classmethod
    def clear_local_data(cls) -> None:
        """
        Clear local development data.

        This has no effect on AWS DynamoDB.
        """

        cls._local_events.clear()

        cls._local_incidents.clear()