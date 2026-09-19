# detector/rules.py

EXPECTED_TOOLS = {
    "summarize_email": {
        "email_tool",
        "drive_tool"
    }
}

SENSITIVE_TARGETS = {
    "credentials",
    "secrets",
    "database",
    "users_table",
    "private_repository",
    "org-repos",
    "internal_api"
}

SENSITIVE_TOOLS = {
    "github_tool",
    "database_tool",
    "internal_api_tool",
    "credential_store"
}

UNTRUSTED_SOURCES = {
    "external_document",
    "external_email",
    "external_share",
    "webpage",
    "external_url",
    "unknown"
}


def check_task_mismatch(event):
    task = event.get("task")
    tool = event.get("tool")

    expected_tools = EXPECTED_TOOLS.get(task, set())

    if expected_tools and tool not in expected_tools:
        return True

    return False


def check_unexpected_tool(event):
    task = event.get("task")
    tool = event.get("tool")

    expected_tools = EXPECTED_TOOLS.get(task, set())

    if expected_tools and tool not in expected_tools:
        return True

    return False


def check_sensitive_access(event):
    target = event.get("target")

    return target in SENSITIVE_TARGETS


def check_cross_system_movement(events):
    tools = []

    for event in events:
        tool = event.get("tool")

        if tool and tool not in tools:
            tools.append(tool)

    return len(tools) >= 3


def check_untrusted_to_sensitive_transition(events):
    """
    Detect untrusted content followed by
    access to a sensitive tool or target.
    """

    untrusted_seen = False

    for event in events:

        source = event.get("source")
        tool = event.get("tool")
        target = event.get("target")

        if source in UNTRUSTED_SOURCES:
            untrusted_seen = True

        if untrusted_seen:

            if (
                tool in SENSITIVE_TOOLS
                or target in SENSITIVE_TARGETS
            ):
                return True

    return False


def check_task_change(events):
    """
    Detect when the agent's task changes during
    a single activity sequence.
    """

    tasks = []

    for event in events:

        task = event.get("task")

        if task and task not in tasks:
            tasks.append(task)

    return len(tasks) > 1