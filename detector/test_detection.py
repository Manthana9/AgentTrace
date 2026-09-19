# detector/test_detection.py

from detector.detection_engine import analyze_events


def print_result(name, result):
    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    print("Risk Level :", result["risk_level"])
    print("Risk Score :", result["risk_score"])
    print("Reasons    :", result["reasons"])
    print("Chain      :", " -> ".join(result["attack_chain"]))


# ============================================================
# TEST 1 — NORMAL AGENT BEHAVIOR
# ============================================================

normal_events = [

    {
        "event_id": "normal_001",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "email",
        "action": "read",
        "target": "inbox",
        "source": "user"
    },

    {
        "event_id": "normal_002",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "drive",
        "action": "read",
        "target": "project_document",
        "source": "email"
    }
]

normal_result = analyze_events(normal_events)

print_result(
    "TEST 1 — NORMAL BEHAVIOR",
    normal_result
)


# ============================================================
# TEST 2 — SUSPICIOUS LATERAL MOVEMENT
# ============================================================

attack_events = [

    {
        "event_id": "attack_001",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "email",
        "action": "read",
        "target": "inbox",
        "source": "user"
    },

    {
        "event_id": "attack_002",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "drive",
        "action": "read",
        "target": "project_document",
        "source": "external_document"
    },

    {
        "event_id": "attack_003",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "github",
        "action": "read_repository",
        "target": "private_repository",
        "source": "external_document"
    },

    {
        "event_id": "attack_004",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "database",
        "action": "query",
        "target": "database",
        "source": "github"
    }
]

attack_result = analyze_events(attack_events)

print_result(
    "TEST 2 — SUSPICIOUS LATERAL MOVEMENT",
    attack_result
)


# ============================================================
# TEST 3 — UNTRUSTED CONTENT → SENSITIVE SYSTEM
# ============================================================

subtle_attack_events = [

    {
        "event_id": "subtle_001",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "email",
        "action": "read",
        "target": "inbox",
        "source": "user"
    },

    {
        "event_id": "subtle_002",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "drive",
        "action": "read",
        "target": "external_document",
        "source": "external_document"
    },

    {
        "event_id": "subtle_003",
        "agent_id": "research-agent-01",
        "task": "summarize_email",
        "tool": "github",
        "action": "read_repository",
        "target": "private_repository",
        "source": "external_document"
    }
]

subtle_result = analyze_events(subtle_attack_events)

print_result(
    "TEST 3 — UNTRUSTED CONTENT → SENSITIVE SYSTEM",
    subtle_result
)