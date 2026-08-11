# ADR 0003: Use a typed Python and TypeScript monorepo

- Status: Accepted
- Date: 2026-08-11

## Context

Google ADK, color/image tooling, and scientific validation are strongest in Python; the incident workspace benefits from the TypeScript/Next.js ecosystem. Cross-boundary drift is a major risk.

## Decision

Use Next.js with strict TypeScript and generated OpenAPI client for web; FastAPI, Pydantic v2, SQLAlchemy 2, and Alembic for services; shared versioned contracts and generated clients in one monorepo.

## Consequences

Two language toolchains are required, but boundaries remain explicit. Handwritten duplicate API types are prohibited. Contract checks are release-blocking.
