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
APT_AUTOMATIC_TIMERS = ("apt-daily.timer", "apt-daily-upgrade.timer")
APT_AUTOMATIC_SERVICES = ("apt-daily.service", "apt-daily-upgrade.service")
APT_AUTOMATIC_UNITS = (*APT_AUTOMATIC_TIMERS, *APT_AUTOMATIC_SERVICES)


class StartupLifecycleTests(unittest.TestCase):
    def _write_executable(self, path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def _run_lifecycle(
        self,
        *,
        now: int = 1_800_000_000,
        generation: str = GENERATION,
        hard_stop_epoch: int | str | None = None,
        timer_deadline: int | None = None,
        systemd_run_fails: bool = False,
        apt_mask_fails: bool = False,
        apt_enabled_state: str = "masked",
        apt_active_state: str = "inactive",
        apt_services_busy: bool = False,
        apt_transition_polls: int = 0,
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
            effective_hard_stop_epoch = 0 if hard_stop_epoch is None else hard_stop_epoch
            if timer_deadline is None:
                try:
                    parsed_hard_stop_epoch = int(effective_hard_stop_epoch)
                    effective_timer_deadline = (
                        min(now + LIFETIME_SECONDS, parsed_hard_stop_epoch)
                        if parsed_hard_stop_epoch > 0
                        else now + LIFETIME_SECONDS
                    )
                except ValueError:
                    effective_timer_deadline = now + LIFETIME_SECONDS
            else:
                effective_timer_deadline = timer_deadline

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
apt_services = {"apt-daily.service", "apt-daily-upgrade.service"}
apt_units = {
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    *apt_services,
}
if arguments and arguments[0] == "mask" and set(arguments[1:]) == apt_units:
    raise SystemExit(1 if os.environ["FAKE_APT_MASK_FAILS"] == "true" else 0)
if len(arguments) == 2 and arguments[0] == "is-enabled" and arguments[1] in apt_units:
    state = os.environ["FAKE_APT_ENABLED_STATE"]
    print(state)
    raise SystemExit(1 if state == "masked" else 0)
if (
    len(arguments) == 4
    and arguments[0] == "show"
    and arguments[1] in apt_services
    and arguments[2:] == ["--property=ActiveState", "--value"]
):
    command_log = pathlib.Path(os.environ["FAKE_COMMAND_LOG"])
    poll_count = sum(
        1
        for line in command_log.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["args"][0:1] == ["show"]
        and json.loads(line)["args"][-2:] == ["--property=ActiveState", "--value"]
    )
    transition_polls = int(os.environ["FAKE_APT_TRANSITION_POLLS"])
    if os.environ["FAKE_APT_SERVICES_BUSY"] == "true":
        print("active")
    elif poll_count <= transition_polls:
        print("activating")
    else:
        print("inactive")
    raise SystemExit(0)
if len(arguments) == 2 and arguments[0] == "is-active" and arguments[1] in apt_units:
    state = os.environ["FAKE_APT_ACTIVE_STATE"]
    print(state)
    raise SystemExit(3 if state == "inactive" else 0)
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
                    "readonly STAGING_HARD_STOP_EPOCH='${staging_hard_stop_epoch}'",
                    "readonly STAGING_HARD_STOP_EPOCH="
                    + shlex.quote(str(effective_hard_stop_epoch)),
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
                .replace(
                    "readonly APT_SERVICE_QUIESCE_ATTEMPTS=180",
                    "readonly APT_SERVICE_QUIESCE_ATTEMPTS=2",
                )
                .replace(
                    "readonly APT_SERVICE_QUIESCE_DELAY_SECONDS=5",
                    "readonly APT_SERVICE_QUIESCE_DELAY_SECONDS=0",
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
                    "FAKE_APT_MASK_FAILS": ("true" if apt_mask_fails else "false"),
                    "FAKE_APT_ENABLED_STATE": apt_enabled_state,
                    "FAKE_APT_ACTIVE_STATE": apt_active_state,
                    "FAKE_APT_SERVICES_BUSY": ("true" if apt_services_busy else "false"),
                    "FAKE_APT_TRANSITION_POLLS": str(apt_transition_polls),
                    "FAKE_TIMER_DEADLINE": str(effective_timer_deadline),
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

    def test_automatic_apt_is_frozen_before_lifecycle_validation(self) -> None:
        result = self._run_lifecycle()
        completed = result["completed"]
        self.assertIsInstance(completed, subprocess.CompletedProcess)
        self.assertEqual(completed.returncode, 0, completed.stderr)

        systemctl_calls = [
            call["args"] for call in result["calls"] if call["command"] == "systemctl"
        ]
        self.assertEqual(systemctl_calls[0], ["mask", *APT_AUTOMATIC_UNITS])
        self.assertEqual(systemctl_calls[1], ["stop", *APT_AUTOMATIC_TIMERS])
        for call in systemctl_calls:
            if call[0] == "stop":
                self.assertTrue(set(call[1:]).isdisjoint(APT_AUTOMATIC_SERVICES))
        expected_verification = [
            command
            for unit in APT_AUTOMATIC_UNITS
            for command in (["is-enabled", unit], ["is-active", unit])
        ]
        verification_calls = [
            call
            for call in systemctl_calls
            if len(call) == 2
            and call[0] in {"is-enabled", "is-active"}
            and call[1] in APT_AUTOMATIC_UNITS
        ]
        self.assertEqual(verification_calls, expected_verification)

        source = STARTUP_TEMPLATE.read_text(encoding="utf-8")
        freeze_index = source.index("\nfreeze_automatic_apt\n")
        lifecycle_index = source.index("\nfresh_lifecycle=false\n")
        self.assertLess(freeze_index, lifecycle_index)

    def test_automatic_apt_waits_for_running_services_without_stopping_them(self) -> None:
        result = self._run_lifecycle(apt_transition_polls=2)
        completed = result["completed"]
        self.assertIsInstance(completed, subprocess.CompletedProcess)
        self.assertEqual(completed.returncode, 0, completed.stderr)

        systemctl_calls = [
            call["args"] for call in result["calls"] if call["command"] == "systemctl"
        ]
        service_wait_calls = [
            call
            for call in systemctl_calls
            if len(call) == 4
            and call[0] == "show"
            and call[1] in APT_AUTOMATIC_SERVICES
            and call[2:] == ["--property=ActiveState", "--value"]
        ]
        self.assertEqual(
            service_wait_calls,
            [
                ["show", unit, "--property=ActiveState", "--value"]
                for _attempt in range(2)
                for unit in APT_AUTOMATIC_SERVICES
            ],
        )
        for call in systemctl_calls:
            if call[0] == "stop":
                self.assertTrue(set(call[1:]).isdisjoint(APT_AUTOMATIC_SERVICES))

    def test_automatic_apt_freeze_failure_powers_off_before_lifecycle_acceptance(self) -> None:
        cases = (
            {"apt_mask_fails": True},
            {"apt_enabled_state": "enabled"},
            {"apt_active_state": "active"},
            {"apt_services_busy": True},
        )
        for options in cases:
            with self.subTest(options=options):
                result = self._run_lifecycle(**options)
                completed = result["completed"]
                self.assertIsInstance(completed, subprocess.CompletedProcess)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIsNone(result["current_target"])
                self.assertNotIn("systemd-run", [call["command"] for call in result["calls"]])
                if options.get("apt_services_busy"):
                    service_wait_calls = [
                        call["args"]
                        for call in result["calls"]
                        if call["command"] == "systemctl"
                        and len(call["args"]) == 4
                        and call["args"][0] == "show"
                        and call["args"][1] in APT_AUTOMATIC_SERVICES
                        and call["args"][2:] == ["--property=ActiveState", "--value"]
                    ]
                    self.assertEqual(
                        service_wait_calls,
                        [
                            ["show", unit, "--property=ActiveState", "--value"]
                            for _attempt in range(2)
                            for unit in APT_AUTOMATIC_SERVICES
                        ],
                    )
                for call in result["calls"]:
                    if call["command"] == "systemctl" and call["args"][0] == "stop":
                        self.assertTrue(set(call["args"][1:]).isdisjoint(APT_AUTOMATIC_SERVICES))
                self.assertIn(
                    ["poweroff"],
                    [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
                )

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

    def test_absolute_hard_stop_caps_generation_timer(self) -> None:
        now = 1_800_000_000
        hard_stop_epoch = now + 3600

        result = self._run_lifecycle(
            now=now,
            hard_stop_epoch=hard_stop_epoch,
        )

        completed = result["completed"]
        self.assertIsInstance(completed, subprocess.CompletedProcess)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        timer_calls = [call for call in result["calls"] if call["command"] == "systemd-run"]
        self.assertEqual(len(timer_calls), 1)
        self.assertIn(f"--on-calendar=@{hard_stop_epoch}", timer_calls[0]["args"])

    def test_reached_absolute_hard_stop_powers_off_before_host_changes(self) -> None:
        now = 1_800_000_000

        result = self._run_lifecycle(now=now, hard_stop_epoch=now)

        completed = result["completed"]
        self.assertIsInstance(completed, subprocess.CompletedProcess)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(result["current_target"])
        self.assertNotIn("systemd-run", [call["command"] for call in result["calls"]])
        self.assertEqual(
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
            [["poweroff"]],
        )

    def test_malformed_absolute_hard_stop_fails_closed(self) -> None:
        result = self._run_lifecycle(hard_stop_epoch="not-an-epoch")

        completed = result["completed"]
        self.assertIsInstance(completed, subprocess.CompletedProcess)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(result["current_target"])
        self.assertNotIn("systemd-run", [call["command"] for call in result["calls"]])
        self.assertEqual(
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
            [["poweroff"]],
        )

    def test_overflowing_absolute_hard_stop_fails_closed(self) -> None:
        result = self._run_lifecycle(hard_stop_epoch="9" * 40)

        completed = result["completed"]
        self.assertIsInstance(completed, subprocess.CompletedProcess)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(result["current_target"])
        self.assertNotIn("systemd-run", [call["command"] for call in result["calls"]])
        self.assertEqual(
            [call["args"] for call in result["calls"] if call["command"] == "systemctl"],
            [["poweroff"]],
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

    def test_workload_startup_recreates_the_compose_network_before_pull(self) -> None:
        startup = STARTUP_TEMPLATE.read_text(encoding="utf-8")

        config_index = startup.index("compose config --quiet")
        down_index = startup.index("compose down --remove-orphans")
        pull_index = startup.index("compose pull")
        workload_index = startup.index("compose up --detach --remove-orphans")

        self.assertLess(config_index, down_index)
        self.assertLess(down_index, pull_index)
        self.assertLess(pull_index, workload_index)


if __name__ == "__main__":
    unittest.main()
