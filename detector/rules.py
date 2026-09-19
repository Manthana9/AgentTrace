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


def check_task_mismatch(event):
    task = event.get("task")
    tool = event.get("tool")

    expected_tools = EXPECTED_TOOLS.get(task, set())

    if expected_tools and tool not in expected_tools:
        return True

    return False


def check_sensitive_access(event):
    target = event.get("target")

    return target in SENSITIVE_TARGETS


def check_unexpected_tool(event):
    task = event.get("task")
    tool = event.get("tool")

    expected_tools = EXPECTED_TOOLS.get(task, set())

    if expected_tools and tool not in expected_tools:
        return True

    return False