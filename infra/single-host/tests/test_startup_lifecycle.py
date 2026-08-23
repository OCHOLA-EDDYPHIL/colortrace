from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

STARTUP_TEMPLATE = Path(__file__).parents[1] / "templates" / "startup.sh.tftpl"
COMPOSE_TEMPLATE = Path(__file__).parents[1] / "templates" / "compose.yaml.tftpl"
GENERATION = "stage-0001"
LIFETIME_SECONDS = 7 * 24 * 60 * 60


class StartupLifecycleTests(unittest.TestCase):
    def _write_executable(self, path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def _run_lifecycle(
        self,
        *,
        now: int = 1_800_000_000,
        generation: str = GENERATION,
        timer_deadline: int | None = None,
        systemd_run_fails: bool = False,
        package_version: str = "1.0",
        setup: Callable[[Path], None] | None = None,
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            control = temporary / "lifecycle"
            root = temporary / "root"
            binaries = temporary / "bin"
            log = temporary / "commands.jsonl"
            binaries.mkdir()
            log.touch()
            if setup is not None:
                control.mkdir(mode=0o700)
                setup(control)

            self._write_executable(
                binaries / "date",
                """#!/usr/bin/env python3
import os
import sys

if sys.argv[1:] == ["+%s"]:
    print(os.environ["FAKE_NOW"])
    raise SystemExit(0)
if len(sys.argv) == 3 and sys.argv[1].startswith("--date=") and sys.argv[2] == "+%s":
    value = sys.argv[1].split("=", 1)[1]
    print(value.removeprefix("@"))
    raise SystemExit(0)
raise SystemExit(2)
""",
            )
            self._write_executable(
                binaries / "systemctl",
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

with pathlib.Path(os.environ["FAKE_COMMAND_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"command": "systemctl", "args": sys.argv[1:]}) + "\\n")

arguments = sys.argv[1:]
if arguments and arguments[0] == "show":
    if "--property=Persistent" in arguments:
        print("yes")
    elif "--property=AccuracyUSec" in arguments:
        print("1s")
    elif "--property=NextElapseUSecRealtime" in arguments:
        print("@" + os.environ["FAKE_TIMER_DEADLINE"])
    else:
        raise SystemExit(2)
raise SystemExit(0)
""",
            )
            self._write_executable(
                binaries / "systemd-run",
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

with pathlib.Path(os.environ["FAKE_COMMAND_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"command": "systemd-run", "args": sys.argv[1:]}) + "\\n")
raise SystemExit(1 if os.environ["FAKE_SYSTEMD_RUN_FAILS"] == "true" else 0)
""",
            )
            self._write_executable(
                binaries / "dpkg-query",
                """#!/usr/bin/env python3
import os
import sys

packages = (
    "ca-certificates",
    "curl",
    "docker-compose",
    "docker.io",
    "iptables",
    "jq",
    "openssl",
)
version = os.environ["FAKE_PACKAGE_VERSION"]
if sys.argv[-1] in packages:
    print(f"ii |{version}", end="")
else:
    for package in packages:
        print(f"ii |{package}|{version}")
""",
            )

            source = STARTUP_TEMPLATE.read_text(encoding="utf-8")
            lifecycle_source = source.split("export DEBIAN_FRONTEND=noninteractive", 1)[0]
            lifecycle_source = (
                lifecycle_source.replace(
                    "readonly STAGING_GENERATION='${staging_generation}'",
                    f"readonly STAGING_GENERATION={shlex.quote(generation)}",
                )
                .replace(
                    "readonly STAGING_LIFETIME_HOURS='${staging_lifetime_hours}'",
                    "readonly STAGING_LIFETIME_HOURS=168",
                )
                .replace(
                    "readonly ROOT_DIR='/srv/colortrace'",
                    f"readonly ROOT_DIR={shlex.quote(str(root))}",
                )
                .replace(
                    "readonly CONTROL_DIR='/var/lib/colortrace-lifecycle'",
                    f"readonly CONTROL_DIR={shlex.quote(str(control))}",
                )
            )
            lifecycle_source = lifecycle_source.replace("$${", "${")
            lifecycle_source += "\nstartup_complete=true\nexit 0\n"
            script = temporary / "lifecycle.sh"
            self._write_executable(script, lifecycle_source)

            completed = subprocess.run(
                [str(script)],
                check=False,
                capture_output=True,
                env={
                    **os.environ,
                    "FAKE_COMMAND_LOG": str(log),
                    "FAKE_NOW": str(now),
                    "FAKE_SYSTEMD_RUN_FAILS": ("true" if systemd_run_fails else "false"),
                    "FAKE_TIMER_DEADLINE": str(timer_deadline or now + LIFETIME_SECONDS),
                    "FAKE_PACKAGE_VERSION": package_version,
                    "PATH": f"{binaries}:{os.environ['PATH']}",
                },
                text=True,
            )
            calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            current_target = (
                os.readlink(control / "current") if (control / "current").is_symlink() else None
            )
            active = control / current_target if current_target else None
            return {
                "completed": completed,
                "calls": calls,
                "current_target": current_target,
                "generation_link": (
                    os.readlink(control / "generation")
                    if (control / "generation").is_symlink()
                    else None
                ),
                "activation_link": (
                    os.readlink(control / "activated-at")
                    if (control / "activated-at").is_symlink()
                    else None
                ),
                "state_generation": (
                    (active / "generation").read_text(encoding="utf-8")
                    if active and (active / "generation").is_file()
                    else None
                ),
                "state_activation": (
                    (active / "activated-at").read_text(encoding="utf-8")
                    if active and (active / "activated-at").is_file()
                    else None
                ),
            }

    def test_new_generation_is_atomically_accepted_before_verified_timer(self) -> None:
        now = 1_800_000_000
        result = self._run_lifecycle(now=now)
        completed = result["completed"]
        self.assertIsInstance(completed, subprocess.CompletedProcess)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["current_target"], f"states/{GENERATION}-{now}")
        self.assertEqual(result["generation_link"], "current/generation")
        self.assertEqual(result["activation_link"], "current/activated-at")
        self.assertEqual(result["state_generation"], GENERATION)
        self.assertEqual(result["state_activation"], str(now))

        timer_calls = [call for call in result["calls"] if call["command"] == "systemd-run"]
        self.assertEqual(len(timer_calls), 1)
        self.assertIn(f"--on-calendar=@{now + LIFETIME_SECONDS}", timer_calls[0]["args"])
        self.assertIn("--timer-property=Persistent=yes", timer_calls[0]["args"])
        self.assertIn("--timer-property=AccuracySec=1s", timer_calls[0]["args"])
        self.assertNotIn(
            ["poweroff"],
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
        )

    def test_existing_generation_keeps_original_activation_time(self) -> None:
        now = 1_800_000_000
        activated_at = now - 3600

        def setup(control: Path) -> None:
            (control / "generation").write_text(GENERATION, encoding="utf-8")
            (control / "activated-at").write_text(f"{activated_at}\n", encoding="utf-8")

        result = self._run_lifecycle(
            now=now,
            timer_deadline=activated_at + LIFETIME_SECONDS,
            setup=setup,
        )
        completed = result["completed"]
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["state_activation"], str(activated_at))
        self.assertEqual(result["current_target"], f"states/{GENERATION}-{activated_at}")

    def test_partial_or_corrupt_record_powers_off_without_arming_timer(self) -> None:
        def setup(control: Path) -> None:
            (control / "generation").write_text(GENERATION, encoding="utf-8")

        result = self._run_lifecycle(setup=setup)
        completed = result["completed"]
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Invalid or interrupted", completed.stderr)
        self.assertNotIn("systemd-run", [call["command"] for call in result["calls"]])
        self.assertIn(
            ["poweroff"],
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
        )

    def test_interrupted_atomic_write_powers_off(self) -> None:
        def setup(control: Path) -> None:
            states = control / "states"
            states.mkdir(mode=0o700)
            (states / ".state-new-aborted").mkdir(mode=0o700)

        result = self._run_lifecycle(setup=setup)
        completed = result["completed"]
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            ["poweroff"],
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
        )

    def test_preexisting_empty_control_directory_is_interrupted_state(self) -> None:
        result = self._run_lifecycle(setup=lambda _control: None)
        completed = result["completed"]
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("systemd-run", [call["command"] for call in result["calls"]])
        self.assertIn(
            ["poweroff"],
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
        )

    def test_managed_package_version_drift_powers_off(self) -> None:
        now = 1_800_000_000
        activated_at = now - 3600

        def setup(control: Path) -> None:
            state_name = f"{GENERATION}-{activated_at}"
            state = control / "states" / state_name
            state.mkdir(parents=True, mode=0o700)
            records = {
                "state-version": "1",
                "generation": GENERATION,
                "activated-at": str(activated_at),
                "package-versions": "".join(
                    f"{package}=1.0\n"
                    for package in sorted(
                        (
                            "ca-certificates",
                            "curl",
                            "docker-compose",
                            "docker.io",
                            "iptables",
                            "jq",
                            "openssl",
                        )
                    )
                ),
            }
            for name, contents in records.items():
                record = state / name
                record.write_text(contents, encoding="utf-8")
                record.chmod(0o400)
            (control / "current").symlink_to(f"states/{state_name}")
            (control / "generation").symlink_to("current/generation")
            (control / "activated-at").symlink_to("current/activated-at")

        result = self._run_lifecycle(
            now=now,
            package_version="2.0",
            setup=setup,
        )
        completed = result["completed"]
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("systemd-run", [call["command"] for call in result["calls"]])
        self.assertIn(
            ["poweroff"],
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
        )

    def test_expired_generation_powers_off(self) -> None:
        now = 1_800_000_000
        activated_at = now - LIFETIME_SECONDS

        def setup(control: Path) -> None:
            (control / "generation").write_text(GENERATION, encoding="utf-8")
            (control / "activated-at").write_text(str(activated_at), encoding="utf-8")

        result = self._run_lifecycle(now=now, setup=setup)
        completed = result["completed"]
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("systemd-run", [call["command"] for call in result["calls"]])
        self.assertIn(
            ["poweroff"],
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
        )

    def test_systemd_run_failure_powers_off(self) -> None:
        result = self._run_lifecycle(systemd_run_fails=True)
        completed = result["completed"]
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual([call["command"] for call in result["calls"]].count("systemd-run"), 1)
        self.assertIn(
            ["poweroff"],
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
        )

    def test_package_inventory_is_generation_bound_and_apt_is_not_repeated(self) -> None:
        source = STARTUP_TEMPLATE.read_text(encoding="utf-8")
        timer_index = source.index("systemd-run \\")
        apt_index = source.index("apt-get update")
        workload_index = source.index("configure_container_metadata_boundary")

        self.assertLess(timer_index, apt_index)
        self.assertLess(timer_index, workload_index)
        self.assertIn("$active_state_dir/package-versions", source)
        self.assertIn('validate_package_record "$state_dir"', source)
        self.assertIn("$${binary:Package}|$${Version}", source)
        self.assertIn('if test "$generation_requires_packages" = true; then', source)
        self.assertIn('mv -T "$temporary_record"', source)

    def test_failure_trap_remains_installed_through_workload_startup(self) -> None:
        source = STARTUP_TEMPLATE.read_text(encoding="utf-8")

        self.assertEqual(source.count("trap 'finish_startup $?' EXIT"), 1)
        self.assertNotIn("trap 'rm -f", source)
        self.assertGreater(source.rindex("startup_complete=true"), source.index("compose ps"))

    def test_workloads_cannot_auto_start_before_resume_gate(self) -> None:
        startup = STARTUP_TEMPLATE.read_text(encoding="utf-8")
        compose = COMPOSE_TEMPLATE.read_text(encoding="utf-8")

        self.assertNotIn("restart: unless-stopped", compose)
        self.assertEqual(compose.count('restart: "no"'), 7)
        timer_index = startup.index("systemd-run \\")
        docker_index = startup.index("systemctl enable --now docker")
        workload_index = startup.index("compose up --detach --remove-orphans")
        self.assertLess(timer_index, docker_index)
        self.assertLess(docker_index, workload_index)


if __name__ == "__main__":
    unittest.main()
