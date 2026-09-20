import { useState } from "react";
import "./App.css";

const API_URL =
  "https://9gf9r8x4n5.execute-api.eu-north-1.amazonaws.com/dev/events";

const DEMO_EVENTS = [
  {
    agent_id: "ResearchAgent",
    timestamp: "2026-09-19T09:01:00Z",
    task: "summarize_email",
    tool: "email",
    action: "read_email",
    target: "project-inbox",
    source: "user_task",
  },
  {
    agent_id: "ResearchAgent",
    timestamp: "2026-09-19T09:02:00Z",
    task: "summarize_email",
    tool: "drive",
    action: "read_document",
    target: "project-document",
    source: "external_document",
  },
  {
    agent_id: "ResearchAgent",
    timestamp: "2026-09-19T09:03:00Z",
    task: "summarize_email",
    tool: "github",
    action: "read_repository",
    target: "internal-repo",
    source: "external_document",
  },
  {
    agent_id: "ResearchAgent",
    timestamp: "2026-09-19T09:04:00Z",
    task: "summarize_email",
    tool: "database",
    action: "query_database",
    target: "customer-database",
    source: "external_document",
  },
];

function App() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [events, setEvents] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [incident, setIncident] = useState(null);
  const [currentEvent, setCurrentEvent] = useState(null);

  const [demoIndex, setDemoIndex] = useState(0);

  // AI explanation state
  const [aiExplanation, setAiExplanation] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  const generateDemoAIExplanation = (detection, currentEvents) => {
    if (!detection) return;

    const riskLevel = String(
      detection.risk_level || "unknown"
    ).toUpperCase();

    const score = detection.risk_score ?? 0;

    const reasons =
      detection.reasons && detection.reasons.length > 0
        ? detection.reasons
        : [
            "The agent accessed resources outside its expected workflow.",
            "The activity crossed multiple systems.",
            "The observed actions do not fully match the original task.",
          ];

    const timeline = currentEvents
      .map(
        (event) =>
          `${event.tool} → ${event.action} → ${event.target}`
      )
      .join(" → ");

    setAiLoading(true);

    setTimeout(() => {
      setAiExplanation({
        title: "AI Security Analysis",
        explanation:
          `AgentTrace detected ${riskLevel} risk with a score of ${score}. ` +
          `The ResearchAgent was originally assigned to summarize emails, ` +
          `but the observed activity moved from the email system to other internal resources. ` +
          `This pattern may indicate that the agent was influenced by external content ` +
          `to use its legitimate permissions outside the intended task.`,
        whySuspicious: reasons,
        attackChain: timeline,
        response: [
          "Restrict or pause the affected agent if the activity is confirmed malicious.",
          "Review the external document or content that triggered the unusual behavior.",
          "Inspect the systems and resources accessed during the sequence.",
          "Review the agent's permissions and reduce unnecessary access.",
        ],
      });

      setAiLoading(false);
    }, 900);
  };

  const sendEvent = async (event) => {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(event),
      });

      if (!response.ok) {
        throw new Error(
          `Backend request failed with status ${response.status}`
        );
      }

      const data = await response.json();

      console.log("AgentTrace backend response:", data);

      const updatedEvents = [
        ...events,
        data.event || event,
      ];

      setCurrentEvent(data.event || event);

      if (data.detection) {
        setAnalysis(data.detection);

        generateDemoAIExplanation(
          data.detection,
          updatedEvents
        );
      }

      setIncident(data.incident || null);

      setEvents(updatedEvents);

      return data;
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Unable to connect to the AgentTrace backend."
      );

      return null;
    } finally {
      setLoading(false);
    }
  };

  const runNextDemoEvent = async () => {
    if (demoIndex >= DEMO_EVENTS.length) {
      setError(
        "Demo sequence completed. Click Reset Demo to run it again."
      );
      return;
    }

    const event = DEMO_EVENTS[demoIndex];

    const result = await sendEvent(event);

    if (result) {
      setDemoIndex((previousIndex) => previousIndex + 1);
    }
  };

  const runFullDemo = async () => {
    setLoading(true);
    setError("");
    setAiExplanation(null);

    let lastResult = null;
    let collectedEvents = [];

    try {
      for (const event of DEMO_EVENTS) {
        const response = await fetch(API_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(event),
        });

        if (!response.ok) {
          throw new Error(
            `Backend request failed with status ${response.status}`
          );
        }

        const data = await response.json();

        console.log("AgentTrace event response:", data);

        lastResult = data;

        const receivedEvent = data.event || event;

        collectedEvents = [
          ...collectedEvents,
          receivedEvent,
        ];

        setCurrentEvent(receivedEvent);

        if (data.detection) {
          setAnalysis(data.detection);
        }

        setIncident(data.incident || null);
        setEvents([...collectedEvents]);

        await new Promise((resolve) =>
          setTimeout(resolve, 700)
        );
      }

      setDemoIndex(DEMO_EVENTS.length);

      if (lastResult?.detection) {
        generateDemoAIExplanation(
          lastResult.detection,
          collectedEvents
        );
      }
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Unable to complete the security analysis."
      );
    } finally {
      setLoading(false);
    }

    return lastResult;
  };

  const resetDemo = () => {
    setEvents([]);
    setAnalysis(null);
    setIncident(null);
    setCurrentEvent(null);
    setDemoIndex(0);
    setError("");
    setAiExplanation(null);
    setAiLoading(false);
  };

  const getRiskClass = () => {
    if (!analysis) return "";

    const level = String(
      analysis.risk_level || ""
    ).toLowerCase();

    if (level === "critical") return "critical";
    if (level === "high") return "high";
    if (level === "medium") return "suspicious";
    if (level === "low") return "normal";

    return "";
  };

  const getRiskScore = () => {
    if (!analysis) return 0;

    return analysis.risk_score ?? 0;
  };

  const getRiskLevel = () => {
    if (!analysis) return "WAITING";

    return String(
      analysis.risk_level || "UNKNOWN"
    ).toUpperCase();
  };

  const getAgentName = () => {
    if (currentEvent?.agent_id) {
      return currentEvent.agent_id;
    }

    if (
      events.length > 0 &&
      events[events.length - 1]?.agent_id
    ) {
      return events[events.length - 1].agent_id;
    }

    return "ResearchAgent";
  };

  const getTask = () => {
    if (currentEvent?.task) {
      return currentEvent.task;
    }

    if (
      events.length > 0 &&
      events[events.length - 1]?.task
    ) {
      return events[events.length - 1].task;
    }

    return "Summarize emails";
  };

  const getTimeline = () => {
    if (
      analysis?.attack_chain &&
      Array.isArray(analysis.attack_chain) &&
      analysis.attack_chain.length > 0
    ) {
      return analysis.attack_chain;
    }

    return events.map((event) => {
      return `${event.tool}:${event.target}`;
    });
  };

  const formatTimelineItem = (item) => {
    if (!item) return "Unknown activity";

    const text = String(item);

    const parts = text.split(":");

    if (parts.length >= 2) {
      const tool = parts[0];
      const target = parts.slice(1).join(":");

      return `${tool.toUpperCase()} → ${target}`;
    }

    return text;
  };

  const getTimelineTime = (index) => {
    if (events[index]?.timestamp) {
      const date = new Date(events[index].timestamp);

      if (!Number.isNaN(date.getTime())) {
        return date.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        });
      }
    }

    const baseHour = 9;
    const minute = String(index + 1).padStart(2, "0");

    return `${String(baseHour).padStart(
      2,
      "0"
    )}:${minute}`;
  };

  const getEvidence = () => {
    if (!analysis) {
      return [
        {
          icon: "⚠️",
          title: "Unexpected tool",
          description:
            "Run a security analysis to receive detection evidence.",
        },
        {
          icon: "🔐",
          title: "Sensitive resource",
          description:
            "Backend detection results will appear here.",
        },
        {
          icon: "🔄",
          title: "Cross-system movement",
          description:
            "The attack chain will be displayed here.",
        },
        {
          icon: "❗",
          title: "Task/action mismatch",
          description:
            "Detection reasons will be displayed here.",
        },
      ];
    }

    const reasonCodes = analysis.reason_codes || [];
    const reasons = analysis.reasons || [];

    const evidenceMap = [
      {
        code: "UNEXPECTED_TOOL",
        icon: "⚠️",
        title: "Unexpected tool",
      },
      {
        code: "SENSITIVE_RESOURCE",
        icon: "🔐",
        title: "Sensitive resource",
      },
      {
        code: "CROSS_SYSTEM_MOVEMENT",
        icon: "🔄",
        title: "Cross-system movement",
      },
      {
        code: "TASK_ACTION_MISMATCH",
        icon: "❗",
        title: "Task/action mismatch",
      },
    ];

    const detectedEvidence = evidenceMap.filter(
      (item) => reasonCodes.includes(item.code)
    );

    if (
      detectedEvidence.length === 0 &&
      reasons.length > 0
    ) {
      return reasons.map((reason, index) => ({
        icon: "⚠️",
        title: `Detection reason ${index + 1}`,
        description: reason,
      }));
    }

    if (detectedEvidence.length === 0) {
      return [
        {
          icon: "ℹ️",
          title: "Detection status",
          description:
            "The backend returned a detection result without mapped reason codes.",
        },
      ];
    }

    return detectedEvidence.map((item) => {
      const reasonIndex = reasonCodes.indexOf(
        item.code
      );

      return {
        icon: item.icon,
        title: item.title,
        description:
          reasons[reasonIndex] ||
          `Detection rule triggered: ${item.code}`,
      };
    });
  };

  const evidence = getEvidence();
  const timeline = getTimeline();

  return (
    <div className="app">

      {/* HEADER */}
      <header className="header">
        <div className="header-left">
          <div className="logo">
            🛡️
          </div>

          <div>
            <h1>AgentTrace</h1>
            <p>AI Agent Security Monitoring</p>
          </div>
        </div>

        <div className="header-right">
          <div className="system-status">
            <span className="status-dot"></span>
            System Active
          </div>
        </div>
      </header>

      <main className="dashboard">

        {/* CONTROL PANEL */}
        <section className="panel control-panel">
          <div className="panel-title">
            <span>Security Analysis</span>
          </div>

          <div className="control-content">
            <p>
              Send simulated AgentTrace activity to the
              backend detection engine and generate an
              AI-assisted security explanation.
            </p>

            <div className="control-buttons">
              <button
                className="analysis-button"
                onClick={runFullDemo}
                disabled={loading}
              >
                {loading
                  ? "Analyzing..."
                  : "▶ Run Security Analysis"}
              </button>

              <button
                className="reset-button"
                onClick={resetDemo}
                disabled={loading}
              >
                ↻ Reset Demo
              </button>
            </div>

            <div className="demo-progress">
              Demo events sent:{" "}
              <strong>{events.length}</strong>{" "}
              / {DEMO_EVENTS.length}
            </div>
          </div>

          {error && (
            <div className="error-message">
              ⚠️ {error}
            </div>
          )}
        </section>

        {/* OVERVIEW */}
        <section className="overview">
          <h2>Security Overview</h2>

          <div className="stats-grid">

            <div className="stat-card">
              <div className="stat-number">
                {events.length > 0 ? 1 : 0}
              </div>

              <div className="stat-label">
                Agents Monitored
              </div>
            </div>

            <div className="stat-card normal">
              <div className="stat-number">
                {analysis &&
                String(analysis.risk_level).toLowerCase() ===
                  "low"
                  ? 1
                  : 0}
              </div>

              <div className="stat-label">
                Normal
              </div>
            </div>

            <div className="stat-card suspicious">
              <div className="stat-number">
                {analysis &&
                String(analysis.risk_level).toLowerCase() ===
                  "medium"
                  ? 1
                  : 0}
              </div>

              <div className="stat-label">
                Suspicious
              </div>
            </div>

            <div className="stat-card critical">
              <div className="stat-number">
                {analysis &&
                ["high", "critical"].includes(
                  String(
                    analysis.risk_level || ""
                  ).toLowerCase()
                )
                  ? 1
                  : 0}
              </div>

              <div className="stat-label">
                Critical
              </div>
            </div>

          </div>
        </section>

        {/* INCIDENT */}
        <section className="panel incident-panel">
          <div className="panel-title">
            <span>Potential LOTA Activity</span>

            <span
              className={`risk-badge ${getRiskClass()}`}
            >
              {analysis
                ? `${getRiskLevel()} — ${getRiskScore()}`
                : "WAITING"}
            </span>
          </div>

          <div className="incident-details">

            <div>
              <strong>Agent</strong>

              <span>
                {getAgentName()}
              </span>
            </div>

            <div>
              <strong>Risk Level</strong>

              <span className="high-risk">
                {analysis
                  ? `${getRiskLevel()} — ${getRiskScore()}`
                  : "Not analyzed"}
              </span>
            </div>

            <div>
              <strong>Task</strong>

              <span>
                {getTask()}
              </span>
            </div>

          </div>

          {analysis && (
            <div className="incident-status">
              <strong>Status:</strong>{" "}
              {analysis.risk_status || "Unknown"}

              {incident && (
                <span className="incident-id">
                  Incident ID:{" "}
                  {incident.incident_id ||
                    incident.id ||
                    "Generated"}
                </span>
              )}
            </div>
          )}
        </section>

        {/* ATTACK TIMELINE */}
        <section className="panel">
          <div className="panel-title">
            <span>Attack Timeline</span>
          </div>

          {timeline.length === 0 ? (
            <div className="empty-state">
              No activity detected yet. Run the security
              analysis to generate an attack timeline.
            </div>
          ) : (
            <div className="timeline">

              {timeline.map((item, index) => {
                const event = events[index];

                return (
                  <div
                    className="timeline-item"
                    key={`${item}-${index}`}
                  >
                    <div className="timeline-time">
                      {getTimelineTime(index)}
                    </div>

                    <div className="timeline-dot"></div>

                    <div className="timeline-content">
                      <strong>
                        {formatTimelineItem(item)}
                      </strong>

                      <p>
                        {event
                          ? `${event.action || "Activity"} on ${
                              event.target ||
                              "resource"
                            }`
                          : "Activity detected in the attack chain."}
                      </p>
                    </div>
                  </div>
                );
              })}

            </div>
          )}
        </section>

        {/* DETECTION EVIDENCE */}
        <section className="panel">
          <div className="panel-title">
            <span>Detection Evidence</span>
          </div>

          <div className="evidence-grid">

            {evidence.map((item, index) => (
              <div
                className="evidence-card"
                key={`${item.title}-${index}`}
              >
                <div className="evidence-icon">
                  {item.icon}
                </div>

                <div>
                  <h4>{item.title}</h4>

                  <p>{item.description}</p>
                </div>
              </div>
            ))}

          </div>
        </section>

        {/* AMAZON BEDROCK */}
        <section className="panel ai-panel">

          <div className="panel-title">
            <span> Amazon Bedrock</span>

            <span className="badge">
              {aiExplanation
                ? "ANALYSIS READY"
                : "BEDROCK LAYER"}
            </span>
          </div>

          {!analysis ? (
            <div className="empty-state">
              <h3>AI explanation waiting for detection</h3>

              <p>
                Run the AgentTrace security analysis first.
                Structured detection evidence will then be
                converted into a human-readable security
                explanation.
              </p>
            </div>
          ) : aiLoading ? (
            <div className="ai-loading">
              <div className="ai-spinner"></div>

              <div>
                <strong>
                  Amazon Bedrock is analyzing the incident...
                </strong>

                <p>
                  Converting detection evidence into a
                  security explanation.
                </p>
              </div>
            </div>
          ) : aiExplanation ? (
            <div className="ai-result">

              <div className="ai-summary">

                <h3>
                  {aiExplanation.title}
                </h3>

                <p>
                  {aiExplanation.explanation}
                </p>

              </div>

              <div className="ai-section">

                <h4>
                  🔍 WHY IS THIS SUSPICIOUS?
                </h4>

                <ul>
                  {aiExplanation.whySuspicious.map(
                    (reason, index) => (
                      <li key={index}>
                        {reason}
                      </li>
                    )
                  )}
                </ul>

              </div>

              <div className="ai-section">

                <h4>
                  🔗 ATTACK CHAIN
                </h4>

                <div className="attack-chain">
                  {aiExplanation.attackChain}
                </div>

              </div>

              <div className="ai-section">

                <h4>
                   RECOMMENDED RESPONSE
                </h4>

                <ul>
                  {aiExplanation.response.map(
                    (item, index) => (
                      <li key={index}>
                        {item}
                      </li>
                    )
                  )}
                </ul>

              </div>

              <div className="bedrock-status">
                <span className="status-dot"></span>

                Structured detection evidence processed
                by the AI explanation layer
              </div>

            </div>
          ) : (
            <p>
              Preparing AI security explanation...
            </p>
          )}

        </section>

        {/* RECOMMENDED RESPONSE */}
        <section className="panel response-panel">

          <div className="panel-title">
            <span>Recommended Response</span>
          </div>

          <div className="response-list">

            <div className="response-item">
              <span>🛑</span>

              <span>
                Restrict agent
              </span>
            </div>

            <div className="response-item">
              <span>🔎</span>

              <span>
                Review triggering content
              </span>
            </div>

            <div className="response-item">
              <span>🖥️</span>

              <span>
                Inspect affected systems
              </span>
            </div>

            <div className="response-item">
              <span>🔐</span>

              <span>
                Review permissions
              </span>
            </div>

          </div>

        </section>

      </main>
    </div>
  );
}

export default App;