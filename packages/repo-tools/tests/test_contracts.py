from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from colortrace_repo.contracts import check_contracts


class ContractPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.contracts = self.root / "packages" / "contracts"
        self.contracts.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _write(self, document: dict[str, object]) -> None:
        (self.contracts / "openapi.json").write_text(json.dumps(document), encoding="utf-8")

    def test_accepts_openapi_31_with_valid_local_example(self) -> None:
        self._write(
            {
                "openapi": "3.1.0",
                "info": {"title": "Synthetic", "version": "1.0.0"},
                "paths": {
                    "/synthetic": {
                        "get": {
                            "operationId": "getSynthetic",
                            "responses": {
                                "200": {
                                    "description": "Synthetic response",
                                    "content": {
                                        "application/json": {
                                            "schema": {"type": "string"},
                                            "example": "value",
                                        }
                                    },
                                }
                            },
                        }
                    }
                },
            }
        )

        self.assertEqual(check_contracts(self.root), [])

    def test_rejects_unresolved_reference_and_invalid_example(self) -> None:
        self._write(
            {
                "openapi": "3.1.0",
                "info": {"title": "Synthetic", "version": "1.0.0"},
                "paths": {
                    "/synthetic": {
                        "get": {
                            "operationId": "getSynthetic",
                            "responses": {
                                "200": {
                                    "description": "Synthetic response",
                                    "content": {
                                        "application/json": {
                                            "schema": {"$ref": "#/components/schemas/Missing"},
                                            "example": 7,
                                        }
                                    },
                                }
                            },
                        }
                    }
                },
            }
        )

        codes = {finding.code for finding in check_contracts(self.root)}

        self.assertIn("contract.ref.invalid", codes)
        self.assertIn("contract.example.invalid", codes)


if __name__ == "__main__":
    unittest.main()
