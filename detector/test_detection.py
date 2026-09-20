from detector.detection_engine import analyze_events


# ============================================================
# TEST 1 — NORMAL BEHAVIOR
# ============================================================

normal_events = [
    {
        "event_id": "evt_normal_001",
        "timestamp": "2026-09-19T10:26:41+00:00",
        "agent_id": "research-agent-test-normal",
        "task": "summarize_email",
        "tool": "email_tool",
        "action": "fetch",
        "target": "inbox",
        "source": "user_task",
    },
    {
        "event_id": "evt_normal_002",
        "timestamp": "2026-09-19T10:26:41+00:00",
        "agent_id": "research-agent-test-normal",
        "task": "summarize_email",
        "tool": "drive_tool",
        "action": "read",
        "target": "project_status_doc",
        "source": "internal_drive",
    },
    {
        "event_id": "evt_normal_003",
        "timestamp": "2026-09-19T10:26:42+00:00",
        "agent_id": "research-agent-test-normal",
        "task": "summarize_email",
        "tool": "email_tool",
        "action": "send",
        "target": "boss",
        "source": "agent",
    },
]


# ============================================================
# TEST 2 — LIVING-OFF-THE-AGENT ATTACK
#
# IMPORTANT:
# The task NEVER changes.
# The agent still believes it is performing:
#     summarize_email
#
# The suspicious behavior is the unexpected sequence of
# legitimate tools after processing an external document.
# ============================================================

attack_events = [
    {
        "event_id": "evt_attack_001",
        "timestamp": "2026-09-19T10:26:40+00:00",
        "agent_id": "research-agent-test-attack",
        "task": "summarize_email",
        "tool": "email_tool",
        "action": "fetch",
        "target": "inbox",
        "source": "user_task",
    },
    {
        "event_id": "evt_attack_002",
        "timestamp": "2026-09-19T10:26:40+00:00",
        "agent_id": "research-agent-test-attack",
        "task": "summarize_email",
        "tool": "drive_tool",
        "action": "read",
        "target": "malicious_doc",
        "source": "external_document",
    },
    {
        "event_id": "evt_attack_003",
        "timestamp": "2026-09-19T10:26:40+00:00",
        "agent_id": "research-agent-test-attack",
        "task": "summarize_email",
        "tool": "github_tool",
        "action": "search_repositories",
        "target": "org-repos",
        "source": "agent",
    },
    {
        "event_id": "evt_attack_004",
        "timestamp": "2026-09-19T10:26:40+00:00",
        "agent_id": "research-agent-test-attack",
        "task": "summarize_email",
        "tool": "database_tool",
        "action": "query_table",
        "target": "users_table",
        "source": "agent",
    },
    {
        "event_id": "evt_attack_005",
        "timestamp": "2026-09-19T10:26:40+00:00",
        "agent_id": "research-agent-test-attack",
        "task": "summarize_email",
        "tool": "internal_api_tool",
        "action": "post_data",
        "target": "internal-service",
        "source": "agent",
    },
]


# ============================================================
# RUN TEST 1
# ============================================================

print("=" * 60)
print("TEST 1 — NORMAL BEHAVIOR")
print("=" * 60)

result = analyze_events(normal_events)

print("Risk Level :", result["risk_level"])
print("Risk Score :", result["risk_score"])
print("Reasons    :", result["reasons"])
print("Chain      :", " -> ".join(result["attack_chain"]))

print("\nExpected:")
print("Risk Level : NORMAL")
print("Risk Score : 0")


# ============================================================
# RUN TEST 2
# ============================================================

print("\n" + "=" * 60)
print("TEST 2 — LIVING-OFF-THE-AGENT ATTACK")
print("=" * 60)

result = analyze_events(attack_events)

print("Risk Level :", result["risk_level"])
print("Risk Score :", result["risk_score"])
print("Reasons    :", result["reasons"])
print("Chain      :", " -> ".join(result["attack_chain"]))

print("\nEvidence:")
for evidence in result["evidence"]:
    print("-", evidence["description"])

print("\nExpected:")
print("Risk Level : HIGH")
print("Attack Chain:")
print("Email → Drive → GitHub → Database → Internal API")