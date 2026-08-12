from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from colortrace_repo.ai_policy import check_ai_policy

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class AiPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        (self.root / "policy").mkdir()
        policy = (REPOSITORY_ROOT / "policy" / "ai-boundary.json").read_text(encoding="utf-8")
        (self.root / "policy" / "ai-boundary.json").write_text(policy, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_allows_google_boundary_and_ignores_development_and_prose(self) -> None:
        (self.root / "pyproject.toml").write_text(
            """
[project]
name = "example"
version = "0.0.0"
dependencies = ["google-adk==1.0.0", "google-genai==1.0.0", "mcp==1.0.0"]

[dependency-groups]
dev = ["openai==1.0.0"]
""".strip()
            + "\n",
            encoding="utf-8",
        )
        (self.root / "config").mkdir()
        (self.root / "config" / "runtime.json").write_text(
            json.dumps(
                {
                    "provider": "vertex-ai",
                    "framework": "google-adk",
                    "model": "gemini-2.5-flash",
                    "mcpServers": {
                        "observability": {
                            "command": "mcp-grafana",
                            "args": ["--stdio"],
                            "transport": "stdio",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        (self.root / "notes.txt").write_text(
            "A provider name in prose is outside the structured policy boundary.\n",
            encoding="utf-8",
        )

        self.assertEqual(check_ai_policy(self.root), [])

    def test_rejects_alternate_runtime_dependency_and_public_mcp(self) -> None:
        (self.root / "pyproject.toml").write_text(
            """
[project]
name = "example"
version = "0.0.0"
dependencies = ["openai==1.0.0"]
""".strip()
            + "\n",
            encoding="utf-8",
        )
        (self.root / "config").mkdir()
        (self.root / "config" / "runtime.json").write_text(
            json.dumps(
                {
                    "provider": "alternate",
                    "mcpServers": {
                        "public": {
                            "transport": "sse",
                            "url": "https://public.invalid/mcp",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        codes = {finding.code for finding in check_ai_policy(self.root)}
        self.assertIn("ai.dependency.disallowed", codes)
        self.assertIn("ai.config.provider", codes)
        self.assertIn("ai.config.transport", codes)
        self.assertIn("ai.config.mcp-public", codes)
        self.assertIn("ai.config.mcp-command", codes)

    def test_rejects_alternate_runtime_sdk_families(self) -> None:
        for dependency in ("litellm", "groq", "together-ai", "smolagents"):
            with self.subTest(ecosystem="python", dependency=dependency):
                (self.root / "pyproject.toml").write_text(
                    f"""
[project]
name = "example"
version = "0.0.0"
dependencies = ["{dependency}==1.0.0"]
""".strip()
                    + "\n",
                    encoding="utf-8",
                )
                codes = {finding.code for finding in check_ai_policy(self.root)}
                self.assertIn("ai.dependency.disallowed", codes)

        for dependency in ("litellm", "groq-sdk", "together-ai", "smolagents"):
            with self.subTest(ecosystem="node", dependency=dependency):
                (self.root / "pyproject.toml").unlink(missing_ok=True)
                (self.root / "package.json").write_text(
                    json.dumps(
                        {
                            "name": "example",
                            "private": True,
                            "dependencies": {dependency: "1.0.0"},
                        }
                    ),
                    encoding="utf-8",
                )
                codes = {finding.code for finding in check_ai_policy(self.root)}
                self.assertIn("ai.dependency.disallowed", codes)

    def test_unclassified_runtime_dependency_fails_closed(self) -> None:
        (self.root / "pyproject.toml").write_text(
            """
[project]
name = "example"
version = "0.0.0"
dependencies = ["strands-agents==1.0.0"]
""".strip()
            + "\n",
            encoding="utf-8",
        )
        codes = {finding.code for finding in check_ai_policy(self.root)}
        self.assertIn("ai.dependency.unclassified", codes)

        (self.root / "pyproject.toml").unlink()
        (self.root / "package.json").write_text(
            json.dumps(
                {
                    "name": "example",
                    "private": True,
                    "dependencies": {"@aws-sdk/client-bedrock-runtime": "1.0.0"},
                }
            ),
            encoding="utf-8",
        )
        codes = {finding.code for finding in check_ai_policy(self.root)}
        self.assertIn("ai.dependency.unclassified", codes)

    def test_explicit_non_ai_runtime_classification_is_required_and_allowed(self) -> None:
        policy_path = self.root / "policy" / "ai-boundary.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["python"]["allowed_non_ai_runtime_packages"] = ["requests"]
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        (self.root / "pyproject.toml").write_text(
            """
[project]
name = "example"
version = "0.0.0"
dependencies = ["requests==1.0.0"]
""".strip()
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(check_ai_policy(self.root), [])

    def test_policy_requires_closed_classification_keys(self) -> None:
        policy_path = self.root / "policy" / "ai-boundary.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        del policy["node"]["allowed_non_ai_runtime_packages"]
        policy_path.write_text(json.dumps(policy), encoding="utf-8")

        codes = {finding.code for finding in check_ai_policy(self.root)}
        self.assertEqual(codes, {"ai.policy.invalid"})


if __name__ == "__main__":
    unittest.main()
