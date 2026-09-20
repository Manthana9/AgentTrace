"""
AgentTrace - Command Center

Interactive mode:
    python main.py
    > run normal
    > run attack
    > run drift
    > quit

Non-interactive / scripted mode:
    python main.py --run normal
    python main.py --run attack
    python main.py --run drift

Each scenario execution receives a fresh AgentTrace session ID.
This prevents events from previous demo runs from contaminating
the current detection sequence.
"""

import argparse
import uuid

from scenarios import (
    run_normal,
    run_attack,
    run_drift,
)


# ============================================================
# COMMANDS
# ============================================================

COMMANDS = {
    "run normal": run_normal,
    "run attack": run_attack,
    "run drift": run_drift,
}


# ============================================================
# DEMO SESSION
# ============================================================

def start_new_session() -> str:
    """
    Create a fresh agent ID for the current scenario.

    The AWS backend stores event history by agent_id,
    so every demo execution gets its own isolated session.

    Example:

        research-agent-01-demo-a31f92c4
    """

    session_id = uuid.uuid4().hex[:8]

    return f"research-agent-01-demo-{session_id}"


# ============================================================
# RUN SCENARIO
# ============================================================

def run_scenario(
    scenario_name: str,
) -> None:
    """
    Start a fresh session and execute one scenario.
    """

    command = f"run {scenario_name}"

    scenario = COMMANDS.get(command)

    if scenario is None:
        print(
            f"Unknown scenario: {scenario_name!r}"
        )
        return

    # --------------------------------------------------------
    # Create isolated demo session
    # --------------------------------------------------------

    agent_id = start_new_session()

    print()
    print("=" * 60)
    print("AgentTrace Security Analysis")
    print("=" * 60)

    print(
        f"Session Agent ID: {agent_id}"
    )

    print(
        f"Scenario: {scenario_name.upper()}"
    )

    print("=" * 60)
    print()

    try:

        # Pass the session explicitly to the scenario.
        scenario(
            agent_id=agent_id
        )

    except KeyboardInterrupt:

        print(
            "\n\nScenario interrupted."
        )

    except Exception as exc:

        print(
            f"\nScenario failed: {exc}"
        )

        raise


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "AgentTrace -- AI Agent Security "
            "Detection Command Center"
        )
    )

    parser.add_argument(
        "--run",
        choices=[
            "normal",
            "attack",
            "drift",
        ],
        help=(
            "Run one scenario immediately "
            "and exit."
        ),
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Scripted mode
    # --------------------------------------------------------

    if args.run:

        run_scenario(
            args.run
        )

        return

    # --------------------------------------------------------
    # Interactive mode
    # --------------------------------------------------------

    print()
    print(
        "=============================================="
    )

    print(
        "        AgentTrace Command Center"
    )

    print(
        "=============================================="
    )

    print()

    print(
        "Available commands:"
    )

    print(
        "  run normal"
    )

    print(
        "  run attack"
    )

    print(
        "  run drift"
    )

    print(
        "  quit"
    )

    print()

    while True:

        try:

            cmd = input("> ").strip().lower()

        except (
            EOFError,
            KeyboardInterrupt,
        ):

            print(
                "\nGoodbye."
            )

            break

        # ----------------------------------------------------
        # Exit
        # ----------------------------------------------------

        if cmd in (
            "quit",
            "exit",
            "q",
        ):

            print(
                "Goodbye."
            )

            break

        # ----------------------------------------------------
        # Run scenario
        # ----------------------------------------------------

        if cmd in COMMANDS:

            scenario_name = cmd.replace(
                "run ",
                "",
                1,
            )

            run_scenario(
                scenario_name
            )

            print()

            continue

        # ----------------------------------------------------
        # Unknown command
        # ----------------------------------------------------

        print(
            f"Unknown command: {cmd!r}"
        )

        print(
            "Try:"
        )

        print(
            "  run normal"
        )

        print(
            "  run attack"
        )

        print(
            "  run drift"
        )

        print(
            "  quit"
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()