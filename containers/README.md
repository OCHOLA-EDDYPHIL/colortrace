# Container builds

All six builds use the repository root as their build context. Select the required definition with `docker build --file containers/Dockerfile.<role> .`.

| Definition | Purpose |
| --- | --- |
| `Dockerfile.dev` | Pinned development, quality, and security toolchain. |
| `Dockerfile.demo` | Network-isolated command-line demonstration. |
| `Dockerfile.runtime` | Single-host API and workflow runtime with the Grafana MCP server. |
| `Dockerfile.web` | React application served by the small Node web server. |
| `Dockerfile.caddy` | TLS and access-control edge. |
| `Dockerfile.observability` | Grafana, Loki, and Tempo build targets. |

Each definition has an adjacent `.dockerignore` file that exposes only its required inputs.
