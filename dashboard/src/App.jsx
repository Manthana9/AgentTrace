import { useState } from "react";
import "./App.css";

const API_URL =
  "https://9gf9r8x4n5.execute-api.eu-north-1.amazonaws.com/dev/events";

/*
 * ============================================================
 * AgentTrace Dashboard
 * ============================================================
 *
 * One legitimate task:
 *
 *     summarize_email
 *
 * Expected behavior:
 *
 *     EMAIL -> DRIVE
 *
 * Potential LOTA behavior:
 *
 *     EMAIL -> DRIVE -> GITHUB -> DATABASE -> INTERNAL API
 *
 * IMPORTANT:
 *
 * The task does NOT change during the attack.
 * AgentTrace detects behavioral deviation from the
 * intended workflow.
 */

// ============================================================
// DEMO EVENTS
// ============================================================

const DEMO_EVENTS = [
  {
    task: "summarize_email",
    tool: "email_tool",
    action: "fetch",
    target: "inbox",
    source: "user_task",
  },
  {
    task: "summarize_email",
    tool: "drive_tool",
    action: "read",
    target: "malicious_doc",
    source: "external_document",
  },
  {
    task: "summarize_email",
    tool: "github_tool",
    action: "search_repositories",
    target: "org-repos",
    source: "agent",
  },
  {
    task: "summarize_email",
    tool: "database_tool",
    action: "query_table",
    target: "users_table",
    source: "agent",
  },
  {
    task: "summarize_email",
    tool: "internal_api_tool",
    action: "post_data",
    target: "internal-service",
    source: "agent",
  },
];


// ============================================================
// APP
// ============================================================

function App() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [events, setEvents] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [incident, setIncident] = useState(null);
  const [currentEvent, setCurrentEvent] = useState(null);

  const [demoIndex, setDemoIndex] = useState(0);
  const [sessionAgentId, setSessionAgentId] = useState(null);

  // Amazon Bedrock explanation
  const [aiExplanation, setAiExplanation] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);


  // ==========================================================
  // BEDROCK RESPONSE
  // ==========================================================

  const handleAIExplanation = (explanation) => {
    if (!explanation) {
      setAiExplanation(null);
      setAiLoading(false);
      return;
    }

    const status = explanation.status || "unknown";

    if (status === "unavailable") {
      setAiExplanation({
        status: "unavailable",
        provider:
          explanation.provider || "Amazon Bedrock",
        model: explanation.model || "",
        title: "AI Explanation Unavailable",
        explanation:
          explanation.message ||
          "Amazon Bedrock is currently unavailable. The AgentTrace detection result remains valid and is shown above.",
        whySuspicious: [],
        attackChain: "",
        response: [],
      });

      setAiLoading(false);
      return;
    }

    setAiExplanation({
      status,
      provider:
        explanation.provider || "Amazon Bedrock",
      model: explanation.model || "",
      title:
        explanation.title ||
        "AI Security Analysis",
      explanation:
        explanation.explanation ||
        "Amazon Bedrock returned no explanation.",
      whySuspicious:
        Array.isArray(
          explanation.why_suspicious
        )
          ? explanation.why_suspicious
          : [],
      attackChain:
        explanation.attack_chain || "",
      response:
        Array.isArray(explanation.response)
          ? explanation.response
          : [],
    });

    setAiLoading(false);
  };


  // ==========================================================
  // GENERATE SESSION ID
  // ==========================================================

  const generateSessionId = () => {
    try {
      if (
        typeof crypto !== "undefined" &&
        crypto.randomUUID
      ) {
        return `research-agent-01-dashboard-${crypto
          .randomUUID()
          .slice(0, 8)}`;
      }
    } catch (err) {
      console.warn(
        "crypto.randomUUID unavailable",
        err
      );
    }

    return `research-agent-01-dashboard-${Math.random()
      .toString(16)
      .slice(2, 10)}`;
  };


  // ==========================================================
  // SEND ONE EVENT
  // ==========================================================

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

      console.log(
        "AgentTrace backend response:",
        data
      );

      const receivedEvent =
        data.event || event;

      const updatedEvents = [
        ...events,
        receivedEvent,
      ];

      setCurrentEvent(receivedEvent);

      if (data.detection) {
        setAnalysis(data.detection);
      }

      if (data.ai_explanation) {
        handleAIExplanation(
          data.ai_explanation
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


  // ==========================================================
  // RUN FULL SECURITY ANALYSIS
  // ==========================================================

  const runFullDemo = async () => {
    setLoading(true);
    setError("");

    setAnalysis(null);
    setIncident(null);
    setAiExplanation(null);
    setAiLoading(false);

    setEvents([]);
    setCurrentEvent(null);
    setDemoIndex(0);

    // Every dashboard execution gets a fresh
    // isolated AgentTrace session.
    const agentId = generateSessionId();

    setSessionAgentId(agentId);

    let lastResult = null;
    let collectedEvents = [];

    try {
      for (
        let index = 0;
        index < DEMO_EVENTS.length;
        index += 1
      ) {
        const event = {
          ...DEMO_EVENTS[index],

          // Same agent/session for all five events.
          agent_id: agentId,

          // Use real execution timestamps.
          timestamp:
            new Date().toISOString(),
        };

        console.log(
          "Sending AgentTrace event:",
          event
        );

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

        console.log(
          "AgentTrace event response:",
          data
        );

        lastResult = data;

        const receivedEvent =
          data.event || event;

        collectedEvents = [
          ...collectedEvents,
          receivedEvent,
        ];

        setCurrentEvent(receivedEvent);
        setEvents([
          ...collectedEvents,
        ]);

        setDemoIndex(index + 1);

        if (data.detection) {
          setAnalysis(data.detection);
        }

        if (data.incident) {
          setIncident(data.incident);
        }

        if (data.ai_explanation) {
          handleAIExplanation(
            data.ai_explanation
          );
        }

        // Small delay so the dashboard visually
        // builds the attack sequence.
        await new Promise((resolve) =>
          setTimeout(resolve, 650)
        );
      }

      // Make absolutely sure the final response
      // is what remains visible.
      if (lastResult?.detection) {
        setAnalysis(
          lastResult.detection
        );
      }

      if (lastResult?.incident) {
        setIncident(
          lastResult.incident
        );
      }

      if (lastResult?.ai_explanation) {
        handleAIExplanation(
          lastResult.ai_explanation
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


  // ==========================================================
  // RESET
  // ==========================================================

  const resetDemo = () => {
    setEvents([]);
    setAnalysis(null);
    setIncident(null);
    setCurrentEvent(null);

    setDemoIndex(0);
    setSessionAgentId(null);

    setError("");
    setAiExplanation(null);
    setAiLoading(false);
  };


  // ==========================================================
  // RISK HELPERS
  // ==========================================================

  const getRiskClass = () => {
    if (!analysis) {
      return "";
    }

    const level = String(
      analysis.risk_level || ""
    ).toLowerCase();

    if (level === "critical") {
      return "critical";
    }

    if (level === "high") {
      return "high";
    }

    if (level === "medium") {
      return "suspicious";
    }

    if (
      level === "low" ||
      level === "normal"
    ) {
      return "normal";
    }

    return "";
  };


  const getRiskScore = () => {
    if (!analysis) {
      return 0;
    }

    return analysis.risk_score ?? 0;
  };


  const getRiskLevel = () => {
    if (!analysis) {
      return "WAITING";
    }

    return String(
      analysis.risk_level || "UNKNOWN"
    ).toUpperCase();
  };


  // ==========================================================
  // AGENT INFORMATION
  // ==========================================================

  const getAgentName = () => {
    if (sessionAgentId) {
      return sessionAgentId;
    }

    if (currentEvent?.agent_id) {
      return currentEvent.agent_id;
    }

    if (
      events.length > 0 &&
      events[events.length - 1]?.agent_id
    ) {
      return events[
        events.length - 1
      ].agent_id;
    }

    return "ResearchAgent";
  };


  const getTask = () => {
    return "Summarize project emails";
  };


  // ==========================================================
  // WORKFLOW
  // ==========================================================

  const getExpectedWorkflow = () => {
    return [
      "EMAIL",
      "DRIVE",
    ];
  };


  const getObservedWorkflow = () => {
    if (events.length === 0) {
      return [];
    }

    return events.map((event) =>
      String(
        event.tool || ""
      ).toUpperCase()
    );
  };


  // ==========================================================
  // ATTACK TIMELINE
  // ==========================================================

  const getTimeline = () => {
    if (
      analysis?.attack_chain &&
      Array.isArray(
        analysis.attack_chain
      ) &&
      analysis.attack_chain.length > 0
    ) {
      return analysis.attack_chain;
    }

    return events.map((event) => {
      return `${event.tool}:${event.target}`;
    });
  };


  const formatTimelineItem = (item) => {
    if (!item) {
      return "Unknown activity";
    }

    const text = String(item);

    const parts = text.split(":");

    if (parts.length >= 2) {
      const tool = parts[0];

      const target = parts
        .slice(1)
        .join(":");

      return `${tool.toUpperCase()} → ${target}`;
    }

    return text.toUpperCase();
  };


  const getTimelineTime = (index) => {
    if (events[index]?.timestamp) {
      const date = new Date(
        events[index].timestamp
      );

      if (!Number.isNaN(date.getTime())) {
        return date.toLocaleTimeString(
          [],
          {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false,
          }
        );
      }
    }

    return "--:--:--";
  };


  // ==========================================================
  // DETECTION EVIDENCE
  // ==========================================================

  const getEvidence = () => {
    if (!analysis) {
      return [
        {
          icon: "⚠️",
          title: "Unexpected tool",
          description:
            "Run the security analysis to identify behavior outside the expected workflow.",
        },
        {
          icon: "🔐",
          title: "Sensitive resource",
          description:
            "Sensitive resource access will be reported by the detection engine.",
        },
        {
          icon: "🔄",
          title: "Cross-system movement",
          description:
            "AgentTrace reconstructs the sequence of systems accessed by the agent.",
        },
        {
          icon: "❗",
          title: "Task/action mismatch",
          description:
            "Actions that do not support the original user task are analyzed as behavioral deviations.",
        },
      ];
    }

    const reasonCodes =
      analysis.reason_codes || [];

    const reasons =
      analysis.reasons || [];

    const evidenceMap = [
      {
        codes: [
          "UNEXPECTED_TOOL",
          "TASK_ACTION_MISMATCH",
        ],
        icon: "⚠️",
        title: "Unexpected tool",
      },
      {
        codes: [
          "SENSITIVE_RESOURCE",
          "SENSITIVE_RESOURCE_ACCESS",
        ],
        icon: "🔐",
        title: "Sensitive resource",
      },
      {
        codes: [
          "CROSS_SYSTEM_MOVEMENT",
        ],
        icon: "🔄",
        title: "Cross-system movement",
      },
      {
        codes: [
          "TASK_ACTION_MISMATCH",
          "TASK_MISMATCH",
        ],
        icon: "❗",
        title: "Task/action mismatch",
      },
      {
        codes: [
          "UNTRUSTED_TO_SENSITIVE_TRANSITION",
        ],
        icon: "🚨",
        title:
          "Untrusted → sensitive transition",
      },
      {
        codes: [
          "REPEATED_UNUSUAL_BEHAVIOR",
        ],
        icon: "📈",
        title:
          "Repeated unusual behavior",
      },
    ];

    const detectedEvidence =
      evidenceMap.filter((item) =>
        item.codes.some((code) =>
          reasonCodes.includes(code)
        )
      );

    if (
      detectedEvidence.length === 0 &&
      reasons.length > 0
    ) {
      return reasons.map(
        (reason, index) => ({
          icon: "⚠️",
          title:
            `Detection reason ${index + 1}`,
          description: reason,
        })
      );
    }

    if (
      detectedEvidence.length === 0
    ) {
      if (
        String(
          analysis.risk_level || ""
        ).toLowerCase() ===
        "normal"
      ) {
        return [
          {
            icon: "✅",
            title: "Normal behavior",
            description:
              "The observed activity remains within the expected workflow.",
          },
        ];
      }

      return [
        {
          icon: "ℹ️",
          title: "Detection status",
          description:
            "The backend returned a detection result without mapped evidence codes.",
        },
      ];
    }

    return detectedEvidence.map(
      (item) => {
        const matchingCode =
          item.codes.find((code) =>
            reasonCodes.includes(code)
          );

        const reasonIndex =
          matchingCode
            ? reasonCodes.indexOf(
                matchingCode
              )
            : -1;

        return {
          icon: item.icon,
          title: item.title,
          description:
            reasonIndex >= 0 &&
            reasons[reasonIndex]
              ? reasons[reasonIndex]
              : `Detection rule triggered: ${
                  matchingCode ||
                  item.codes[0]
                }`,
        };
      }
    );
  };


  // ==========================================================
  // DERIVED DATA
  // ==========================================================

  const evidence = getEvidence();

  const timeline = getTimeline();

  const expectedWorkflow =
    getExpectedWorkflow();

  const observedWorkflow =
    getObservedWorkflow();

  const hasBehaviorDeviation =
    observedWorkflow.length > 2;


  // ==========================================================
  // RENDER
  // ==========================================================

  return (
    <div className="app">

      {/* ================================================== */}
      {/* HEADER */}
      {/* ================================================== */}

      <header className="header">

        <div className="header-left">

          <div className="logo">
            🛡️
          </div>

          <div>
            <h1>AgentTrace</h1>

            <p>
              AI Agent Security Monitoring
            </p>
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

        {/* ================================================== */}
        {/* SECURITY ANALYSIS */}
        {/* ================================================== */}

        <section className="panel control-panel">

          <div className="panel-title">
            <span>
              Security Analysis
            </span>
          </div>


          <div className="control-content">

            <p>
              AgentTrace observes a trusted AI
              agent performing a legitimate task
              and detects when its behavior
              deviates from the expected workflow.
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

              Activity events observed:{" "}

              <strong>
                {events.length}
              </strong>

              {" "} / {DEMO_EVENTS.length}

            </div>

          </div>


          {error && (
            <div className="error-message">
              ⚠️ {error}
            </div>
          )}

        </section>


        {/* ================================================== */}
        {/* AGENT INTENT */}
        {/* ================================================== */}

        <section className="panel">

          <div className="panel-title">
            <span>
              Agent Intent
            </span>
          </div>


          <div className="incident-details">

            <div>
              <strong>
                Agent
              </strong>

              <span>
                {getAgentName()}
              </span>
            </div>


            <div>
              <strong>
                User Task
              </strong>

              <span>
                {getTask()}
              </span>
            </div>


            <div>
              <strong>
                Expected Workflow
              </strong>

              <span>
                {expectedWorkflow.join(
                  " → "
                )}
              </span>
            </div>

          </div>

        </section>


        {/* ================================================== */}
        {/* OBSERVED BEHAVIOR */}
        {/* ================================================== */}

        <section className="panel">

          <div className="panel-title">

            <span>
              Observed Behavior
            </span>

            {hasBehaviorDeviation && (
              <span className="risk-badge suspicious">
                BEHAVIOR DEVIATION
              </span>
            )}

          </div>


          {observedWorkflow.length === 0 ? (

            <div className="empty-state">
              No agent activity observed yet.
            </div>

          ) : (

            <div
              className="attack-chain"
              style={{
                marginTop: "10px",
              }}
            >
              {observedWorkflow.join(
                " → "
              )}
            </div>

          )}

        </section>


        {/* ================================================== */}
        {/* SECURITY OVERVIEW */}
        {/* ================================================== */}

        <section className="overview">

          <h2>
            Security Overview
          </h2>


          <div className="stats-grid">

            {/* Agents */}

            <div className="stat-card">

              <div className="stat-number">
                {events.length > 0 ? 1 : 0}
              </div>

              <div className="stat-label">
                Agents Monitored
              </div>

            </div>


            {/* Normal */}

            <div className="stat-card normal">

              <div className="stat-number">

                {analysis &&
                String(
                  analysis.risk_level || ""
                ).toLowerCase() ===
                  "normal"
                  ? 1
                  : 0}

              </div>

              <div className="stat-label">
                Normal
              </div>

            </div>


            {/* Suspicious */}

            <div className="stat-card suspicious">

              <div className="stat-number">

                {analysis &&
                ["medium"].includes(
                  String(
                    analysis.risk_level || ""
                  ).toLowerCase()
                )
                  ? 1
                  : 0}

              </div>

              <div className="stat-label">
                Suspicious
              </div>

            </div>


            {/* High Risk */}

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
                High Risk
              </div>

            </div>

          </div>

        </section>


        {/* ================================================== */}
        {/* INCIDENT */}
        {/* ================================================== */}

        <section className="panel incident-panel">

          <div className="panel-title">

            <span>
              Potential LOTA Activity
            </span>

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
              <strong>
                Agent
              </strong>

              <span>
                {getAgentName()}
              </span>
            </div>


            <div>
              <strong>
                Risk Level
              </strong>

              <span className="high-risk">
                {analysis
                  ? `${getRiskLevel()} — ${getRiskScore()}`
                  : "Not analyzed"}
              </span>
            </div>


            <div>
              <strong>
                User Task
              </strong>

              <span>
                {getTask()}
              </span>
            </div>

          </div>


          {analysis && (

            <div className="incident-status">

              <strong>
                Status:
              </strong>{" "}

              {incident?.risk_status ||
                incident?.status ||
                analysis.status ||
                "Potentially Suspicious"}


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


        {/* ================================================== */}
        {/* ATTACK TIMELINE */}
        {/* ================================================== */}

        <section className="panel">

          <div className="panel-title">

            <span>
              Attack Timeline
            </span>

          </div>


          {timeline.length === 0 ? (

            <div className="empty-state">

              No activity detected yet.

              Run the security analysis to
              generate the agent activity
              timeline.

            </div>

          ) : (

            <div className="timeline">

              {timeline.map(
                (item, index) => {

                  const event =
                    events[index];

                  return (

                    <div
                      className="timeline-item"
                      key={`${item}-${index}`}
                    >

                      <div className="timeline-time">

                        {getTimelineTime(
                          index
                        )}

                      </div>


                      <div className="timeline-dot"></div>


                      <div className="timeline-content">

                        <strong>

                          {formatTimelineItem(
                            item
                          )}

                        </strong>


                        <p>

                          {event
                            ? `${
                                event.action ||
                                "Activity"
                              } on ${
                                event.target ||
                                "resource"
                              }`
                            : "Activity detected in the attack chain."}

                        </p>

                      </div>

                    </div>

                  );

                }
              )}

            </div>

          )}

        </section>


        {/* ================================================== */}
        {/* DETECTION EVIDENCE */}
        {/* ================================================== */}

        <section className="panel">

          <div className="panel-title">

            <span>
              Detection Evidence
            </span>

          </div>


          <div className="evidence-grid">

            {evidence.map(
              (item, index) => (

                <div
                  className="evidence-card"
                  key={`${item.title}-${index}`}
                >

                  <div className="evidence-icon">
                    {item.icon}
                  </div>


                  <div>

                    <h4>
                      {item.title}
                    </h4>

                    <p>
                      {item.description}
                    </p>

                  </div>

                </div>

              )
            )}

          </div>

        </section>


        {/* ================================================== */}
        {/* AMAZON BEDROCK */}
        {/* ================================================== */}

        <section className="panel ai-panel">

          <div className="panel-title">

            <span>
              Amazon Bedrock
            </span>


            <span className="badge">

              {aiExplanation?.status ===
              "unavailable"
                ? "BEDROCK UNAVAILABLE"
                : aiExplanation
                ? "ANALYSIS READY"
                : "AI EXPLANATION LAYER"}

            </span>

          </div>


          {!analysis ? (

            <div className="empty-state">

              <h3>
                AI explanation waiting
                for detection
              </h3>

              <p>
                Run the AgentTrace security
                analysis first. The structured
                detection result will then be
                passed to the Amazon Bedrock
                explanation layer.
              </p>

            </div>

          ) : aiLoading ? (

            <div className="ai-loading">

              <div className="ai-spinner"></div>

              <div>

                <strong>
                  Amazon Bedrock is analyzing
                  the incident...
                </strong>

                <p>
                  Converting detection evidence
                  into a human-readable security
                  explanation.
                </p>

              </div>

            </div>

          ) : aiExplanation ? (

            <div className="ai-result">

              {/* ------------------------------------------ */}
              {/* BEDROCK UNAVAILABLE */}
              {/* ------------------------------------------ */}

              {aiExplanation.status ===
              "unavailable" ? (

                <div className="ai-summary">

                  <h3>
                    {aiExplanation.title}
                  </h3>

                  <p>
                    {aiExplanation.explanation}
                  </p>


                  <div
                    className="bedrock-status"
                    style={{
                      marginTop: "15px",
                    }}
                  >

                    <span className="status-dot"></span>

                    Detection engine remains
                    operational independently
                    of the AI explanation layer.

                  </div>

                </div>

              ) : (

                <>

                  {/* -------------------------------------- */}
                  {/* SUMMARY */}
                  {/* -------------------------------------- */}

                  <div className="ai-summary">

                    <h3>
                      {aiExplanation.title}
                    </h3>

                    <p>
                      {aiExplanation.explanation}
                    </p>

                  </div>


                  {/* -------------------------------------- */}
                  {/* WHY SUSPICIOUS */}
                  {/* -------------------------------------- */}

                  {aiExplanation
                    .whySuspicious
                    .length > 0 && (

                    <div className="ai-section">

                      <h4>
                        🔍 WHY IS THIS SUSPICIOUS?
                      </h4>

                      <ul>

                        {aiExplanation
                          .whySuspicious
                          .map(
                            (
                              reason,
                              index
                            ) => (

                              <li
                                key={index}
                              >
                                {reason}
                              </li>

                            )
                          )}

                      </ul>

                    </div>

                  )}


                  {/* -------------------------------------- */}
                  {/* ATTACK CHAIN */}
                  {/* -------------------------------------- */}

                  {aiExplanation
                    .attackChain && (

                    <div className="ai-section">

                      <h4>
                        🔗 ATTACK CHAIN
                      </h4>

                      <div className="attack-chain">

                        {Array.isArray(
                          aiExplanation.attackChain
                        )
                          ? aiExplanation.attackChain.join(
                              " → "
                            )
                          : aiExplanation.attackChain}

                      </div>

                    </div>

                  )}


                  {/* -------------------------------------- */}
                  {/* RESPONSE */}
                  {/* -------------------------------------- */}

                  {aiExplanation.response
                    .length > 0 && (

                    <div className="ai-section">

                      <h4>
                        RECOMMENDED RESPONSE
                      </h4>

                      <ul>

                        {aiExplanation
                          .response
                          .map(
                            (
                              item,
                              index
                            ) => (

                              <li
                                key={index}
                              >
                                {item}
                              </li>

                            )
                          )}

                      </ul>

                    </div>

                  )}


                  <div className="bedrock-status">

                    <span className="status-dot"></span>

                    Explanation generated by{" "}
                    {aiExplanation.provider ||
                      "Amazon Bedrock"}

                    {aiExplanation.model
                      ? ` · ${aiExplanation.model}`
                      : ""}

                  </div>

                </>

              )}

            </div>

          ) : (

            <div className="empty-state">

              <p>
                Detection completed. Waiting
                for the Amazon Bedrock explanation
                response.
              </p>

            </div>

          )}

        </section>


        {/* ================================================== */}
        {/* RECOMMENDED RESPONSE */}
        {/* ================================================== */}

        <section className="panel response-panel">

          <div className="panel-title">

            <span>
              Recommended Response
            </span>

          </div>


          <div className="response-list">

            <div className="response-item">

              <span>
                🛑
              </span>

              <span>
                Restrict or pause the affected
                agent if the activity is confirmed
                malicious
              </span>

            </div>


            <div className="response-item">

              <span>
                🔎
              </span>

              <span>
                Review the external content that
                influenced the agent
              </span>

            </div>


            <div className="response-item">

              <span>
                🖥️
              </span>

              <span>
                Inspect the systems and resources
                accessed during the sequence
              </span>

            </div>


            <div className="response-item">

              <span>
                🔐
              </span>

              <span>
                Review the agent's permissions
                and reduce unnecessary access
              </span>

            </div>

          </div>

        </section>

      </main>

    </div>
  );
}


export default App;