"""
Step 7 (improved): The Master Switch (Command Center)

Interactive mode:
    python main.py
    > run normal
    > run attack
    > run drift
    > quit

Non-interactive / scripted mode (handy for a timed demo):
    python main.py --run normal
    python main.py --run attack
    python main.py --run drift
"""

import argparse

from scenarios import run_normal, run_attack, run_drift

COMMANDS = {
    "run normal": run_normal,
    "run attack": run_attack,
    "run drift": run_drift,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Emitter -- Command Center")
    parser.add_argument(
        "--run",
        choices=["normal", "attack", "drift"],
        help="Run one scenario immediately and exit (skips the interactive prompt).",
    )
    args = parser.parse_args()

    if args.run:
        COMMANDS[f"run {args.run}"]()
        return

    print("Agent Emitter -- Command Center")
    print("Commands: 'run normal', 'run attack', 'run drift', 'quit'\n")

    while True:
        cmd = input("> ").strip().lower()

        if cmd in ("quit", "exit", "q"):
            print("Goodbye.")
            break
        elif cmd in COMMANDS:
            COMMANDS[cmd]()
        else:
            print(f"Unknown command: {cmd!r}. Try 'run normal', 'run attack', 'run drift', or 'quit'.")


if __name__ == "__main__":
    main()