# ADR 0004: Restrict submitted runtime AI to Gemini and Google ADK

- Status: Accepted
- Date: 2026-08-11

## Context

The hackathon requires Google AI/agent technology, and mixed runtime providers create compliance, security, and reproducibility risk.

## Decision

Use a pinned stable Gemini Flash model on Vertex AI and Google ADK for Python as the sole submitted runtime model/provider and agent framework. CI scans dependencies, endpoints, environment names, containers, and IaC for prohibited alternatives.

## Consequences

No OpenAI, Anthropic, AWS AI, Microsoft AI, local LLM, or third-party agent framework may enter release runtime paths. Model outages fail closed. Provider/model/prompt/tool/policy versions are recorded per invocation.
