# AgentTrace

### AI Agent Security Detection Engine for Living-Off-the-Agent (LOTA) Activity

[![Live Demo](https://img.shields.io/badge/Live-Demo-00C853)](https://agent-trace-one.vercel.app)
[![AWS](https://img.shields.io/badge/Backend-AWS-orange)](https://aws.amazon.com/)
[![Python](https://img.shields.io/badge/Python-3.x-blue)](https://www.python.org/)
[![React](https://img.shields.io/badge/Frontend-React-61DAFB)](https://react.dev/)

> **AgentTrace detects when a trusted AI agent is manipulated into using its legitimate permissions as a path to other systems.**

## 🚨 Problem

AI agents are increasingly connected to tools such as email, cloud storage, Git repositories, databases and internal APIs.

This creates a new security problem:

An attacker may influence an otherwise trusted agent and make it use its existing authenticated tools in an unexpected sequence.

Because these actions can appear individually legitimate, traditional monitoring may fail to identify the complete attack path.

This behavior is referred to in this project as **Living-Off-the-Agent (LOTA)** activity.

## 💡 Solution

AgentTrace monitors AI-agent tool activity and analyzes the sequence of actions rather than looking at individual tool calls in isolation.

It detects behavioral deviations such as:

- Unexpected tool usage
- Access to sensitive resources
- Cross-system movement
- Transitions from untrusted content to sensitive systems
- Tool usage inconsistent with the agent's assigned task

When suspicious behavior is detected, AgentTrace generates:

- Risk score
- Risk level
- Detection reasons
- Evidence
- Observed workflow
- Expected workflow
- Attack chain
- Recommended response context

## 🔥 Demonstrated Attack Scenario

The demo uses a simulated research agent whose legitimate task is:

```text
summarize_email