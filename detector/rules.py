# detector/rules.py

EXPECTED_TOOLS = {
    "summarize_email": {
        "email",
        "drive"
    }
}

SENSITIVE_TARGETS = {
    "credentials",
    "secrets",
    "database",
    "private_repository",
    "internal_api"
}

UNTRUSTED_SOURCES = {
    "external_document",
    "external_email",
    "webpage",
    "external_url",
    "unknown"
}

SENSITIVE_TOOLS = {
    "github",
    "database",
    "internal_api",
    "credential_store"
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
    """
    Detect movement across multiple systems.
    """

    tools = []

    for event in events:
        tool = event.get("tool")

        if tool and tool not in tools:
            tools.append(tool)

    return len(tools) >= 3


def check_untrusted_to_sensitive_transition(events):
    """
    Detects when the agent processes untrusted external
    content and subsequently accesses a sensitive system.
    """

    untrusted_seen = False

    for event in events:

        source = event.get("source")
        tool = event.get("tool")
        target = event.get("target")

        # Step 1: untrusted content enters the agent workflow
        if source in UNTRUSTED_SOURCES:
            untrusted_seen = True

        # Step 2: agent subsequently accesses a sensitive system
        if untrusted_seen:

            if (
                tool in SENSITIVE_TOOLS
                or target in SENSITIVE_TARGETS
            ):
                return True

    return False