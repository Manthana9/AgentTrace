# detector/rules.py

"""
AgentTrace Detection Rules

These rules define the behavioral baseline used by AgentTrace.

Core idea:

    Legitimate task
          ↓
    Expected tools
          ↓
    Observe actual behavior
          ↓
    Detect unexpected tool usage,
    sensitive access, and cross-system movement.

The agent's task does NOT need to change for suspicious
behavior to be detected.
"""


# ============================================================
# EXPECTED TOOLS
# ============================================================

EXPECTED_TOOLS = {
    "summarize_email": {
        "email_tool",
        "drive_tool",
    }
}


# ============================================================
# TOOL ALIASES
# ============================================================

# The local simulator uses names such as:
#
#     email_tool
#     drive_tool
#
# while the dashboard demo may send:
#
#     email
#     drive
#
# Normalize both representations.

TOOL_ALIASES = {
    "email": "email_tool",
    "drive": "drive_tool",
    "github": "github_tool",
    "database": "database_tool",
    "internal_api": "internal_api_tool",
    "spreadsheet": "spreadsheet_tool",
}


def normalize_tool(tool):
    """
    Convert dashboard/local tool names into one
    canonical representation.
    """

    if not tool:
        return None

    tool = str(tool).strip().lower()

    return TOOL_ALIASES.get(tool, tool)


# ============================================================
# SENSITIVE TARGETS
# ============================================================

SENSITIVE_TARGETS = {
    "credentials",
    "secrets",
    "database",
    "users_table",
    "private_repository",
    "org-repos",
    "internal_api",
    "internal-service",
}


# ============================================================
# SENSITIVE TOOLS
# ============================================================

SENSITIVE_TOOLS = {
    "github_tool",
    "database_tool",
    "internal_api_tool",
    "credential_store",
}


# ============================================================
# UNTRUSTED SOURCES
# ============================================================

UNTRUSTED_SOURCES = {
    "external_document",
    "external_email",
    "external_share",
    "webpage",
    "external_url",
    "unknown",
}


# ============================================================
# EXPECTED TOOL CHECK
# ============================================================

def check_task_mismatch(event):
    """
    Determine whether an event uses a tool that is not
    expected for the current task.

    Example:

        Task:
            summarize_email

        Expected:
            email_tool
            drive_tool

        Observed:
            github_tool

    Result:
        True
    """

    task = event.get("task")
    tool = normalize_tool(event.get("tool"))

    expected_tools = {
        normalize_tool(item)
        for item in EXPECTED_TOOLS.get(task, set())
    }

    if expected_tools and tool not in expected_tools:
        return True

    return False


# ============================================================
# UNEXPECTED TOOL CHECK
# ============================================================

def check_unexpected_tool(event):
    """
    Detect unexpected tool usage for the current task.

    This is intentionally kept as a separate function from
    check_task_mismatch() so the detection engine can expose
    both concepts independently if needed.
    """

    return check_task_mismatch(event)


# ============================================================
# SENSITIVE ACCESS CHECK
# ============================================================

def check_sensitive_access(event):
    """
    Detect access to sensitive resources or systems.
    """

    target = event.get("target")
    tool = normalize_tool(event.get("tool"))

    normalized_target = (
        str(target).strip().lower()
        if target
        else None
    )

    if normalized_target in SENSITIVE_TARGETS:
        return True

    if tool in SENSITIVE_TOOLS:
        return True

    return False


# ============================================================
# CROSS-SYSTEM MOVEMENT
# ============================================================

def check_cross_system_movement(events):
    """
    Detect movement across multiple distinct tools/systems.

    Three or more distinct systems in one task sequence
    are considered cross-system movement.
    """

    tools = []

    for event in events:

        tool = normalize_tool(event.get("tool"))

        if tool and tool not in tools:
            tools.append(tool)

    return len(tools) >= 3


# ============================================================
# UNTRUSTED → SENSITIVE TRANSITION
# ============================================================

def check_untrusted_to_sensitive_transition(events):
    """
    Detect untrusted content followed by sensitive activity.

    Example:

        external_document
              ↓
        github_tool
              ↓
        database_tool

    This is important because the attack model assumes that
    attacker-controlled content can influence a trusted agent.
    """

    untrusted_seen = False

    for event in events:

        source = event.get("source")

        tool = normalize_tool(
            event.get("tool")
        )

        target = event.get("target")

        normalized_target = (
            str(target).strip().lower()
            if target
            else None
        )

        # --------------------------------------------
        # Untrusted content observed
        # --------------------------------------------

        if source in UNTRUSTED_SOURCES:
            untrusted_seen = True
            continue

        # --------------------------------------------
        # Sensitive activity after untrusted content
        # --------------------------------------------

        if untrusted_seen:

            if (
                tool in SENSITIVE_TOOLS
                or normalized_target in SENSITIVE_TARGETS
            ):
                return True

    return False