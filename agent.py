"""
Step 4: The "ResearchAgent" Brain

Holds an ID + current task and exposes thin wrappers around the tools it's
allowed to call, so scenario scripts read like a story.
"""

import config
import tools


class ResearchAgent:
    def __init__(self, agent_id: str = None):
        self.agent_id = agent_id or config.AGENT_ID
        self.task = None

    def set_task(self, task: str) -> None:
        print(f"[{self.agent_id}] task set to: {task!r}")
        self.task = task

    def fetch_email(self, target: str = "inbox") -> str:
        return tools.email_tool(task=self.task, action="fetch", target=target)

    def send_email(self, target: str = "boss") -> str:
        return tools.email_tool(task=self.task, action="send", target=target)

    def read_drive_doc(self, target: str) -> str:
        return tools.drive_tool(task=self.task, target=target)

    def search_github(self, target: str = "org-repos") -> str:
        return tools.github_tool(task=self.task, target=target)

    def query_database(self, target: str = "users_table") -> str:
        return tools.database_tool(task=self.task, target=target)

    def post_to_api(self, target: str, data: str) -> str:
        return tools.internal_api_tool(task=self.task, target=target, data=data)

    def read_spreadsheet(self, target: str = "shared_credentials_sheet") -> str:
        return tools.spreadsheet_tool(task=self.task, target=target)