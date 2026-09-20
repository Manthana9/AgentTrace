"""
AgentTrace - ResearchAgent

Represents the AI agent being monitored.

The agent receives one legitimate user task and exposes
thin wrappers around its available tools.

AgentTrace does NOT change the task when suspicious behavior
occurs. Instead, the detection engine observes whether the
agent's tool usage deviates from the intended workflow.
"""

import config
import tools


class ResearchAgent:
    def __init__(self, agent_id: str = None):
        self.agent_id = agent_id or config.AGENT_ID
        self.task = None

    def set_task(self, task: str) -> None:
        """
        Set the legitimate task assigned to the agent.

        The task remains unchanged during execution.
        AgentTrace detects suspicious behavior from the
        observed tool/action sequence.
        """
        print(f"[{self.agent_id}] task set to: {task!r}")
        self.task = task

    # ---------------------------------------------------------
    # EMAIL
    # ---------------------------------------------------------

    def fetch_email(self, target: str = "inbox") -> str:
        """
        Fetch email as part of the normal workflow.
        """
        return tools.email_tool(
            task=self.task,
            action="fetch",
            target=target,
            agent_id=self.agent_id,
        )

    def send_email(self, target: str = "boss") -> str:
        """
        Send an email.
        """
        return tools.email_tool(
            task=self.task,
            action="send",
            target=target,
            agent_id=self.agent_id,
        )

    # ---------------------------------------------------------
    # DRIVE
    # ---------------------------------------------------------

    def read_drive_doc(self, target: str) -> str:
        """
        Read a document from the drive.
        """
        return tools.drive_tool(
            task=self.task,
            target=target,
            agent_id=self.agent_id,
        )

    # ---------------------------------------------------------
    # GITHUB
    # ---------------------------------------------------------

    def search_github(self, target: str = "org-repos") -> str:
        """
        Search repositories.

        For the summarize_email task this is outside
        the expected workflow and should be detected
        by AgentTrace when it occurs.
        """
        return tools.github_tool(
            task=self.task,
            target=target,
            agent_id=self.agent_id,
        )

    # ---------------------------------------------------------
    # DATABASE
    # ---------------------------------------------------------

    def query_database(self, target: str = "users_table") -> str:
        """
        Query a database.

        This represents access to a sensitive system
        that is not required for the email-summary task.
        """
        return tools.database_tool(
            task=self.task,
            target=target,
            agent_id=self.agent_id,
        )

    # ---------------------------------------------------------
    # INTERNAL API
    # ---------------------------------------------------------

    def post_to_api(self, target: str, data: str) -> str:
        """
        Send data to an internal API.

        This can represent the final step in a suspicious
        cross-system activity chain.
        """
        return tools.internal_api_tool(
            task=self.task,
            target=target,
            data=data,
            agent_id=self.agent_id,
        )

    # ---------------------------------------------------------
    # SPREADSHEET
    # ---------------------------------------------------------

    def read_spreadsheet(
        self,
        target: str = "shared_credentials_sheet"
    ) -> str:
        """
        Read a spreadsheet.

        This tool is intentionally available to the agent
        so the detection engine can identify inappropriate
        access when it occurs.
        """
        return tools.spreadsheet_tool(
            task=self.task,
            target=target,
            agent_id=self.agent_id,
        )