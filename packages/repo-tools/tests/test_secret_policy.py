from __future__ import annotations

import re
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
GITLEAKS_CONFIG = REPOSITORY_ROOT / ".gitleaks.toml"


def _synthetic_token() -> str:
    return "ct_" + "test_" + "A" * 32


class SecretPolicyTest(unittest.TestCase):
    def test_custom_rule_matches_runtime_only_synthetic_fixture(self) -> None:
        with GITLEAKS_CONFIG.open("rb") as handle:
            configuration = tomllib.load(handle)
        rule = next(
            item
            for item in configuration["rules"]
            if item["id"] == "colortrace-synthetic-test-token"
        )

        self.assertIsNotNone(re.search(rule["regex"], _synthetic_token()))

    def test_gitleaks_rejects_temporary_synthetic_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "dist").mkdir()
            (root / "dist" / "synthetic.env").write_text(
                f"SYNTHETIC_TOKEN={_synthetic_token()}\n", encoding="utf-8"
            )
            result = subprocess.run(
                [
                    "gitleaks",
                    "dir",
                    "--no-banner",
                    "--config",
                    str(GITLEAKS_CONFIG),
                    "--redact",
                    "--exit-code",
                    "17",
                    str(root),
                ],
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(result.returncode, 17, result.stderr)


if __name__ == "__main__":
    unittest.main()
