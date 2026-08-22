# ColorTrace

## Development

Local development requires Docker and GNU Make. Bootstrap the pinned
toolchain and workspace dependencies, then run the complete offline check suite:

```sh
make bootstrap
make check
```

These local commands require no cloud or service credentials.

## Local demonstration

From a clean checkout, run:

```sh
make demo
```

The command builds an immutable image for the current commit, starts it without
network access, creates a deterministic synthetic color incident, and displays
the proposed simulator plan. Type the requested approval phrase to authorize
one local action. The resulting JSON shows the human approval, service-only
dispatch, action outcome, unchanged safe-frame digest, side-effect-free replay,
and exact commit, tree, image, and configuration bindings. Private run receipts
are retained under `.cache/` at the path printed by the command.

The demonstration does not require Grafana, Vertex AI, cloud credentials, or a
hosted service. It exposes no network endpoint and does not include the private
Grafana MCP binary. It uses only generated data and an ephemeral local simulator
workspace; it is not a production deployment or a statistical reliability
claim.

Successful output is one JSON receipt with `action.action_count` set to `1`,
`replay.generation_unchanged` set to `true`, and
`safety.safe_frame_digest_equal` set to `true`, followed by the private receipt
directory.

If approval is withheld or invalid, no action is admitted and the simulator
publication remains unchanged. To remove the exact demo container or image
reference after an interrupted run, use:

```sh
make demo-clean
```

No external or shared product state is mutated. Rollback consists of stopping
the demo and running that cleanup command. Retained JSON receipts may be removed
separately when they are no longer needed.

## License

Apache License 2.0. See [LICENSE](LICENSE).
