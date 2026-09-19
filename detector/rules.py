# detector/rules.py

# Tools that are normally allowed for each task.
EXPECTED_TOOLS = {
    "summarize_email": {
        "email",
        "drive"
    }
}

# Resources that should be treated as sensitive.
SENSITIVE_TARGETS = {
    "credentials",
    "secrets",
    "database",
    "private_repository",
    "internal_api"
}


def check_task_mismatch(event):
    """
    Checks whether the agent is using a tool
    that does not normally belong to its assigned task.
    """

    task = event.get("task")
    tool = event.get("tool")

    expected_tools = EXPECTED_TOOLS.get(task, set())

    if expected_tools and tool not in expected_tools:
        return True

    return False


def check_unexpected_tool(event):
    """
    Checks whether the current tool is unexpected
    for the agent's assigned task.
    """

    task = event.get("task")
    tool = event.get("tool")

    expected_tools = EXPECTED_TOOLS.get(task, set())

    if expected_tools and tool not in expected_tools:
        return True

    return False


def check_sensitive_access(event):
    """
    Checks whether the agent accessed a sensitive resource.
    """

    target = event.get("target")

    return target in SENSITIVE_TARGETS


def check_cross_system_movement(events):
    """
    Detects movement across multiple systems/tools
    during the same agent task.

    Example:
    email -> drive -> github -> database

    Three or more different systems are considered
    suspicious in this prototype.
    """

    tools = []

    for event in events:
        tool = event.get("tool")

        if tool and tool not in tools:
            tools.append(tool)

    return len(tools) >= 3