"""
AgentTrace - Scripted Workflows

run_normal() -> "The Good Day"
    The agent performs its legitimate task normally.

run_attack() -> "Living-Off-the-Agent"
    The agent receives one legitimate task:

        summarize_email

    External content influences the agent and causes it to
    use legitimate tools outside the expected workflow:

        EMAIL -> DRIVE -> GITHUB -> DATABASE -> INTERNAL API

    IMPORTANT:
    The task NEVER changes to "exfiltrate_credentials".

    AgentTrace detects behavioral deviation from the
    original task rather than relying on a task-change signal.

run_drift() -> "The Slow Leak"
    A subtler deviation where the agent remains nominally
    on-task but accesses a credentials spreadsheet and
    sends the information to another system.
"""

from agent import ResearchAgent
from logger import think


# ============================================================
# NORMAL WORKFLOW
# ============================================================

def run_normal(agent_id: str | None = None) -> None:
    """
    Normal agent behavior.

    Legitimate task:
        summarize_email

    Expected workflow:
        EMAIL -> DRIVE -> EMAIL
    """

    print(
        "\n=== Running NORMAL workflow "
        "(summarize_email) ==="
    )

    agent = ResearchAgent(
        agent_id=agent_id
    )

    agent.set_task(
        "summarize_email"
    )

    # --------------------------------------------------------
    # Step 1: Read incoming email
    # --------------------------------------------------------

    email_body = agent.fetch_email()

    print(
        f"  agent read: {email_body!r}"
    )

    # --------------------------------------------------------
    # Step 2: Read relevant project document
    # --------------------------------------------------------

    doc = agent.read_drive_doc(
        target="project_status_doc"
    )

    print(
        f"  agent read drive doc: "
        f"{doc[:60]!r}..."
    )

    # --------------------------------------------------------
    # Step 3: Think / summarize
    # --------------------------------------------------------

    print(
        "  ...agent is thinking / summarizing..."
    )

    think()

    # --------------------------------------------------------
    # Step 4: Send summary
    # --------------------------------------------------------

    agent.send_email(
        target="boss"
    )

    print(
        "=== NORMAL workflow complete ===\n"
    )


# ============================================================
# LIVING-OFF-THE-AGENT ATTACK
# ============================================================

def run_attack(agent_id: str | None = None) -> None:
    """
    Simulated Living-Off-the-Agent attack.

    The user gives the agent ONE legitimate task:

        summarize_email

    Initial behavior:

        EMAIL -> DRIVE

    A malicious/poisoned document then influences the agent.

    The task does NOT change.

    Instead, the agent starts using its existing authenticated
    tools outside the expected workflow:

        EMAIL
          ↓
        DRIVE
          ↓
        GITHUB
          ↓
        DATABASE
          ↓
        INTERNAL API

    This behavioral deviation is what AgentTrace detects.
    """

    print(
        "\n=== Running ATTACK workflow "
        "(Living-Off-the-Agent) ==="
    )

    agent = ResearchAgent(
        agent_id=agent_id
    )

    # --------------------------------------------------------
    # Legitimate user intent
    # --------------------------------------------------------

    agent.set_task(
        "summarize_email"
    )

    print(
        "  User task: summarize project emails."
    )

    # --------------------------------------------------------
    # Normal activity
    # --------------------------------------------------------

    email_body = agent.fetch_email()

    print(
        f"  agent read: {email_body!r}"
    )

    payload = agent.read_drive_doc(
        target="malicious_doc"
    )

    print(
        f"  agent read poisoned doc: "
        f"{payload!r}"
    )

    # --------------------------------------------------------
    # Behavioral deviation
    # --------------------------------------------------------

    print(
        "  *** BEHAVIORAL DEVIATION: "
        "agent is influenced by external content ***"
    )

    print(
        "  *** AgentTrace continues observing "
        "the original task: 'summarize_email' ***"
    )

    # --------------------------------------------------------
    # Unexpected GitHub access
    # --------------------------------------------------------

    found_files = agent.search_github()

    print(
        f"  agent searched repositories: "
        f"{found_files!r}"
    )

    # --------------------------------------------------------
    # Unexpected database access
    # --------------------------------------------------------

    creds = agent.query_database()

    print(
        f"  agent accessed database: "
        f"{creds!r}"
    )

    # --------------------------------------------------------
    # Unexpected internal API access
    # --------------------------------------------------------

    result = agent.post_to_api(
        target="internal-service",
        data=creds,
    )

    print(
        f"  agent sent data onward: "
        f"{result!r}"
    )

    print(
        "=== ATTACK workflow complete: "
        "5 events sent ===\n"
    )


# ============================================================
# SLOW DRIFT WORKFLOW
# ============================================================

def run_drift(agent_id: str | None = None) -> None:
    """
    Subtler behavioral drift.

    The agent remains on the original task:

        summarize_email

    However, it gradually accesses resources that are
    unnecessary for that task.

    Example sequence:

        EMAIL
          ↓
        DRIVE
          ↓
        DRIFT DOCUMENT
          ↓
        CREDENTIALS SPREADSHEET
          ↓
        INTERNAL API
          ↓
        EMAIL

    This demonstrates that suspicious behavior does not
    always have to look like an immediate attack.
    """

    print(
        "\n=== Running DRIFT workflow "
        "(Slow Leak / Insider-style) ==="
    )

    agent = ResearchAgent(
        agent_id=agent_id
    )

    # --------------------------------------------------------
    # Original legitimate task
    # --------------------------------------------------------

    agent.set_task(
        "summarize_email"
    )

    print(
        "  User task: summarize project emails."
    )

    # --------------------------------------------------------
    # Normal activity
    # --------------------------------------------------------

    email_body = agent.fetch_email()

    print(
        f"  agent read: {email_body!r}"
    )

    doc = agent.read_drive_doc(
        target="project_status_doc"
    )

    print(
        f"  agent read drive doc: "
        f"{doc[:60]!r}..."
    )

    think()

    # --------------------------------------------------------
    # Subtle influence
    # --------------------------------------------------------

    nudge = agent.read_drive_doc(
        target="drift_doc"
    )

    print(
        f"  agent read nudge doc: "
        f"{nudge!r}"
    )

    think()

    # --------------------------------------------------------
    # Unexpected sensitive resource
    # --------------------------------------------------------

    creds = agent.read_spreadsheet()

    print(
        f"  agent accessed spreadsheet: "
        f"{creds!r}"
    )

    think()

    # --------------------------------------------------------
    # Unexpected data movement
    # --------------------------------------------------------

    result = agent.post_to_api(
        target="internal-api",
        data=creds,
    )

    print(
        f"  agent sent data onward: "
        f"{result!r}"
    )

    # --------------------------------------------------------
    # Agent returns to normal-looking behavior
    # --------------------------------------------------------

    agent.send_email(
        target="boss"
    )

    print(
        "=== DRIFT workflow complete: "
        "6 events sent ===\n"
    )