SHELL := /bin/sh

TOOL_IMAGE := colortrace-dev:phase1
GITLEAKS_IMAGE := zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
TELEMETRY_IMAGE := grafana/otel-lgtm@sha256:bb182ac3174a20923fa58f00d1790fa71eb06cc0150078c0b0e8feb9e6611492
TRIVY_IMAGE := aquasec/trivy@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c
HOST_UID := $(shell id -u)
HOST_GID := $(shell id -g)
WORKSPACE := $(CURDIR)
CACHE_ROOT ?= $(WORKSPACE)/.cache
CACHE_ROOT := $(abspath $(CACHE_ROOT))
CACHE_HOME := $(CACHE_ROOT)/home
UV_CACHE := $(CACHE_ROOT)/uv
UV_PROJECT_ENVIRONMENT := $(CACHE_ROOT)/venv
PNPM_STORE := $(CACHE_ROOT)/pnpm
TERRAFORM_PLUGIN_CACHE := $(CACHE_ROOT)/terraform-plugins
SECURITY_EVIDENCE_HOST := $(WORKSPACE)/.cache/security-evidence
SECURITY_EVIDENCE_CONTAINER := /workspace/.cache/security-evidence
SECURITY_CANDIDATE_SHA ?= $(shell git rev-parse HEAD)
SECURITY_REQUIRE_IMAGES ?= false
DEMO_CONFIG := config/demo/local-demo.json
DEMO_APPROVAL ?=
DEMO_REMOVE_IMAGE ?= false
export DEMO_APPROVAL
export DEMO_REMOVE_IMAGE
TOOL_INPUT_SHA256 := $(shell test ! -f containers/Dockerfile.dev || sha256sum containers/Dockerfile.dev | cut -d ' ' -f 1)
PYTEST_WORKERS ?= 2
PYTHON_DISTRIBUTIONS := colortrace-api colortrace-evaluation colortrace-fixture \
	colortrace-grafana-mcp colortrace-investigation \
	colortrace-recovery colortrace-repo colortrace-response-plans \
	colortrace-simulator colortrace-telemetry colortrace-validator \
	colortrace-vertical-slice

TOOL_RUN := docker run --rm \
	--user $(HOST_UID):$(HOST_GID) \
	--volume $(WORKSPACE):/workspace \
	--volume $(CACHE_ROOT):$(CACHE_ROOT) \
	--workdir /workspace \
	--env CI=true \
	--env HOME=$(CACHE_HOME) \
	--env UV_CACHE_DIR=$(UV_CACHE) \
	--env UV_PROJECT_ENVIRONMENT=$(UV_PROJECT_ENVIRONMENT) \
	--env TF_PLUGIN_CACHE_DIR=$(TERRAFORM_PLUGIN_CACHE) \
	$(TOOL_IMAGE)

TOOL_RUN_OFFLINE := docker run --rm \
	--network none \
	--pull=never \
	--user $(HOST_UID):$(HOST_GID) \
	--volume $(WORKSPACE):/workspace \
	--volume $(CACHE_ROOT):$(CACHE_ROOT) \
	--workdir /workspace \
	--env CI=true \
	--env HOME=$(CACHE_HOME) \
	--env UV_CACHE_DIR=$(UV_CACHE) \
	--env UV_PROJECT_ENVIRONMENT=$(UV_PROJECT_ENVIRONMENT) \
	--env TF_PLUGIN_CACHE_DIR=$(TERRAFORM_PLUGIN_CACHE) \
	$(TOOL_IMAGE)

TOOL_RUN_HOST := docker run --rm \
	--network host \
	--pull=never \
	--user $(HOST_UID):$(HOST_GID) \
	--volume $(WORKSPACE):/workspace \
	--volume $(CACHE_ROOT):$(CACHE_ROOT) \
	--workdir /workspace \
	--env CI=true \
	--env HOME=$(CACHE_HOME) \
	--env UV_CACHE_DIR=$(UV_CACHE) \
	--env UV_PROJECT_ENVIRONMENT=$(UV_PROJECT_ENVIRONMENT) \
	--env TF_PLUGIN_CACHE_DIR=$(TERRAFORM_PLUGIN_CACHE) \
	$(TOOL_IMAGE)

.PHONY: bootstrap bootstrap-quality bootstrap-security build-tools build-quality-tools \
	build-security-tools ensure-gitleaks-image ensure-telemetry-image ensure-tool-image \
	ensure-trivy-image prepare-cache format generate generate-fixture check check-fast \
	check-format check-lint check-typecheck check-unit check-contract \
	check-generated check-license check-policy check-secret check-secret-fixture check-telemetry \
	check-terraform check-wheel-license \
	check-bootstrap demo demo-clean demo-image demo-smoke final-image-cleanup final-image-evidence \
	security-evidence

prepare-cache:
	@mkdir -p "$(WORKSPACE)/.cache" "$(CACHE_HOME)" "$(UV_CACHE)" "$(PNPM_STORE)" "$(TERRAFORM_PLUGIN_CACHE)" "$(UV_PROJECT_ENVIRONMENT)"

ensure-tool-image:
	@set -eu; \
	current="$$(docker image inspect --format '{{ index .Config.Labels "org.colortrace.tool-input-sha256" }}' $(TOOL_IMAGE) 2>/dev/null || true)"; \
	if test "$$current" = "$(TOOL_INPUT_SHA256)"; then \
		echo "Reusing integrity-bound $(TOOL_IMAGE)"; \
	else \
		docker build --pull --file containers/Dockerfile.dev \
			--label "org.colortrace.tool-input-sha256=$(TOOL_INPUT_SHA256)" \
			--tag $(TOOL_IMAGE) .; \
	fi

ensure-gitleaks-image:
	@docker image inspect $(GITLEAKS_IMAGE) >/dev/null 2>&1 || docker pull $(GITLEAKS_IMAGE)

ensure-telemetry-image:
	@docker image inspect $(TELEMETRY_IMAGE) >/dev/null 2>&1 || docker pull $(TELEMETRY_IMAGE)

ensure-trivy-image:
	@docker image inspect $(TRIVY_IMAGE) >/dev/null 2>&1 || docker pull $(TRIVY_IMAGE)

build-tools: ensure-tool-image ensure-gitleaks-image ensure-telemetry-image ensure-trivy-image

build-quality-tools: ensure-tool-image ensure-gitleaks-image ensure-telemetry-image

build-security-tools: ensure-tool-image ensure-gitleaks-image ensure-trivy-image

bootstrap: prepare-cache build-tools
	$(TOOL_RUN) uv sync --locked --all-groups --all-packages --all-extras
	$(TOOL_RUN) pnpm install --frozen-lockfile --store-dir $(PNPM_STORE)
	$(TOOL_RUN) terraform -chdir=infra/single-host init -backend=false -input=false

bootstrap-quality: prepare-cache build-quality-tools
	$(TOOL_RUN) uv sync --locked --all-groups --all-packages --all-extras
	$(TOOL_RUN) pnpm install --frozen-lockfile --store-dir $(PNPM_STORE)
	$(TOOL_RUN) terraform -chdir=infra/single-host init -backend=false -input=false

bootstrap-security: prepare-cache build-security-tools
	$(TOOL_RUN) uv sync --locked --all-groups --all-packages --all-extras

format: prepare-cache
	$(TOOL_RUN) uv run ruff format .
	$(TOOL_RUN) uv run ruff check --fix .
	$(TOOL_RUN) pnpm run format

generate: prepare-cache
	$(TOOL_RUN) pnpm run generate

FIXTURE_BUNDLE ?= /workspace/.cache/fixtures/ct-shadowed-lut-v1/runtime-bundle
FIXTURE_ORACLE ?= /workspace/.cache/fixtures/ct-shadowed-lut-v1/offline-oracle
FIXTURE_VALIDATION ?= /workspace/.cache/fixtures/ct-shadowed-lut-v1/validation

generate-fixture: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-fixture generate \
		--bundle $(FIXTURE_BUNDLE) --oracle $(FIXTURE_ORACLE)
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-fixture validate \
		--scenario $(FIXTURE_BUNDLE)
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-validator request \
		--bundle $(FIXTURE_BUNDLE) --request-id fixture-validation \
		--incident-id fixture-incident --output $(FIXTURE_VALIDATION)/request.json
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-validator validate \
		--bundle $(FIXTURE_BUNDLE) --request $(FIXTURE_VALIDATION)/request.json \
		--output $(FIXTURE_VALIDATION)/result.json

demo-image:
	@set -eu; \
	candidate="$$(git rev-parse HEAD)"; \
	test "$${#candidate}" -eq 40; \
	case "$$candidate" in (*[!0-9a-f]*) exit 1;; esac; \
	git diff --quiet; \
	git diff --cached --quiet; \
	test -z "$$(git ls-files --others --exclude-standard)"; \
	candidate_tree="$$(git rev-parse HEAD^{tree})"; \
	source_date_epoch="$$(git show -s --format=%ct HEAD)"; \
	image_ref="colortrace-demo:$$candidate"; \
	docker buildx build --pull=false --provenance=false --load \
		--file containers/Dockerfile.demo --target demo-runtime \
		--build-arg SOURCE_COMMIT="$$candidate" \
		--build-arg SOURCE_TREE="$$candidate_tree" \
		--build-arg SOURCE_DATE_EPOCH="$$source_date_epoch" \
		--tag "$$image_ref" .; \
	test "$$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$$image_ref")" = "$$candidate"; \
	test "$$(docker image inspect --format '{{ index .Config.Labels "org.colortrace.source-tree" }}' "$$image_ref")" = "$$candidate_tree"; \
	test "$$(docker image inspect --format '{{ index .Config.Labels "org.colortrace.runtime-profile" }}' "$$image_ref")" = local-demo; \
	docker run --rm --network none --read-only --cap-drop ALL \
		--entrypoint /bin/sh "$$image_ref" -ceu \
		'test ! -e /usr/local/bin/mcp-grafana'

demo: demo-image prepare-cache
	@set -eu; \
	candidate="$$(git rev-parse HEAD)"; \
	candidate_tree="$$(git rev-parse HEAD^{tree})"; \
	image_ref="colortrace-demo:$$candidate"; \
	image_digest="$$(docker image inspect --format '{{.Id}}' "$$image_ref")"; \
	case "$$image_digest" in (sha256:[0-9a-f][0-9a-f]*) ;; (*) exit 1;; esac; \
	test "$$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$$image_digest")" = "$$candidate"; \
	test "$$(docker image inspect --format '{{ index .Config.Labels "org.colortrace.source-tree" }}' "$$image_digest")" = "$$candidate_tree"; \
	test "$$(docker image inspect --format '{{ index .Config.Labels "org.colortrace.runtime-profile" }}' "$$image_digest")" = local-demo; \
	container="colortrace-demo-$$candidate"; \
	if docker container inspect "$$container" >/dev/null 2>&1; then \
		echo "demo container name is already in use" >&2; \
		exit 1; \
	fi; \
	evidence_root="$$(mktemp -d "$(CACHE_ROOT)/demo-$$candidate.XXXXXX")"; \
	chmod 0700 "$$evidence_root"; \
	install -m 0444 "$(WORKSPACE)/$(DEMO_CONFIG)" "$$evidence_root/local-demo.json"; \
	cleanup() { docker rm --force "$$container" >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT HUP INT TERM; \
	run_demo() { \
		docker run --rm --interactive --name "$$container" \
			--network none --read-only --cap-drop ALL --security-opt no-new-privileges \
			--pids-limit 256 --memory 1g \
			--tmpfs /tmp/colortrace:rw,nosuid,nodev,size=512m,uid=65532,gid=65532,mode=0700 \
			--mount type=bind,src="$$evidence_root/local-demo.json",dst=/config/local-demo.json,readonly \
			--entrypoint /opt/colortrace/bin/python \
			"$$image_digest" -m colortrace_api.demo \
				--config /config/local-demo.json \
				--workspace /tmp/colortrace/workspace \
				--source-commit "$$candidate" \
				--source-tree "$$candidate_tree" \
				--image-digest "$$image_digest" "$$@"; \
	}; \
	if test -n "$${DEMO_APPROVAL}"; then \
		run_demo --approval "$${DEMO_APPROVAL}" > "$$evidence_root/run.json"; \
	else \
		run_demo > "$$evidence_root/run.json"; \
	fi; \
	if docker container inspect "$$container" >/dev/null 2>&1; then \
		echo "demo container cleanup failed" >&2; \
		exit 1; \
	fi; \
	image_removed=false; \
	if test "$${DEMO_REMOVE_IMAGE}" = true; then \
		docker image rm "$$image_ref" >/dev/null; \
		if docker image inspect "$$image_ref" >/dev/null 2>&1; then \
			echo "demo image cleanup failed" >&2; \
			exit 1; \
		fi; \
		image_removed=true; \
	elif test "$${DEMO_REMOVE_IMAGE}" != false; then \
		echo "DEMO_REMOVE_IMAGE must be true or false" >&2; \
		exit 1; \
	fi; \
	printf '%s\n' \
		"{\"schema\":\"colortrace-demo-cleanup/v1\",\"container_absent\":true,\"ephemeral_workspace_removed\":true,\"image_reference_removed\":$$image_removed}" \
		> "$$evidence_root/cleanup.json"; \
	(cd "$$evidence_root" && sha256sum cleanup.json run.json > SHA256SUMS); \
	trap - EXIT HUP INT TERM; \
	sed -n '1p' "$$evidence_root/run.json"; \
	echo "Evidence: $$evidence_root"

demo-smoke:
	@$(MAKE) --no-print-directory demo \
		DEMO_APPROVAL=APPROVE_COLORTRACE_SIMULATOR_ACTION \
		DEMO_REMOVE_IMAGE=true \
		CACHE_ROOT="$(CACHE_ROOT)"

demo-clean:
	@set -eu; \
	candidate="$$(git rev-parse HEAD)"; \
	container="colortrace-demo-$$candidate"; \
	image_ref="colortrace-demo:$$candidate"; \
	if docker container inspect "$$container" >/dev/null 2>&1; then \
		label="$$(docker container inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$$container")"; \
		test "$$label" = "$$candidate"; \
		docker rm --force "$$container" >/dev/null; \
	fi; \
	if docker image inspect "$$image_ref" >/dev/null 2>&1; then \
		label="$$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$$image_ref")"; \
		profile="$$(docker image inspect --format '{{ index .Config.Labels "org.colortrace.runtime-profile" }}' "$$image_ref")"; \
		test "$$label" = "$$candidate"; \
		test "$$profile" = local-demo; \
		docker image rm "$$image_ref" >/dev/null; \
	fi; \
	! docker container inspect "$$container" >/dev/null 2>&1; \
	! docker image inspect "$$image_ref" >/dev/null 2>&1; \
	echo "demo container and image reference cleanup verified"

check-format: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline ruff format --check .
	$(TOOL_RUN_OFFLINE) pnpm run format:check

check-lint: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline ruff check .
	$(TOOL_RUN_OFFLINE) pnpm run lint

check-typecheck: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline mypy
	$(TOOL_RUN_OFFLINE) pnpm run typecheck

check-unit: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline pytest --numprocesses $(PYTEST_WORKERS) --dist loadscope
	$(TOOL_RUN_OFFLINE) uv run --offline pytest deploy/test_runtime_entrypoint.py
	$(TOOL_RUN_OFFLINE) pnpm run test
	$(TOOL_RUN_OFFLINE) node --test deploy/web-server.test.mjs

check-contract: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo contracts

check-generated: prepare-cache
	$(TOOL_RUN_OFFLINE) pnpm run generate:check
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo generated

check-license: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo dependencies
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo distribution

check-wheel-license: prepare-cache
	$(TOOL_RUN_OFFLINE) sh -eu -c '\
		wheel_root="$$(mktemp -d /workspace/.cache/distribution-wheels.XXXXXX)"; \
		install_root="$$(mktemp -d /workspace/.cache/distribution-install.XXXXXX)"; \
		trap '\''chmod -R u+w "$$wheel_root" "$$install_root" 2>/dev/null || true; rm -rf "$$wheel_root" "$$install_root"'\'' EXIT HUP INT TERM; \
		for package in $(PYTHON_DISTRIBUTIONS); do \
			uv build --offline --wheel --package "$$package" --out-dir "$$wheel_root"; \
		done; \
		uv run --offline colortrace-repo distribution-wheels --directory "$$wheel_root"; \
		uv pip install --offline --python "$(UV_PROJECT_ENVIRONMENT)/bin/python" \
			--target "$$install_root" --no-deps "$$wheel_root"/*.whl; \
		cd /tmp; \
		PYTHONPATH="$$install_root" "$(UV_PROJECT_ENVIRONMENT)/bin/python" -P \
			/workspace/packages/repo-tools/tests/installed_wheel_schemas.py "$$install_root"'

check-policy: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo ai-policy
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo actions
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo deployment

check-terraform: prepare-cache
	$(TOOL_RUN_OFFLINE) terraform -chdir=infra/single-host fmt -check -recursive
	$(TOOL_RUN_OFFLINE) terraform -chdir=infra/single-host validate
	$(TOOL_RUN_OFFLINE) terraform -chdir=infra/single-host test -no-color
	$(TOOL_RUN_OFFLINE) python -m unittest discover \
		-s infra/single-host/tests -p 'test_*.py' -v
	$(TOOL_RUN_OFFLINE) bash -n infra/single-host/scripts/*.sh \
		infra/single-host/templates/startup.sh.tftpl

check-telemetry: prepare-cache
	@set -eu; \
	suite_root="$$(mktemp -d "$(WORKSPACE)/.cache/telemetry-suite.XXXXXX")"; \
	private_root="$$(mktemp -d)"; \
	container_root="/workspace$${suite_root#$(WORKSPACE)}"; \
	project_name="colortrace-telemetry-$$$$"; \
	cleanup() { \
		docker compose --project-name "$$project_name" \
			--file config/telemetry/compose.yaml down --volumes --remove-orphans >/dev/null 2>&1 || true; \
		test -n "$$suite_root" && chmod -R u+w "$$suite_root" 2>/dev/null || true; \
		test -n "$$suite_root" && rm -rf "$$suite_root"; \
		test -n "$$private_root" && chmod -R u+w "$$private_root" 2>/dev/null || true; \
		test -n "$$private_root" && rm -rf "$$private_root"; \
	}; \
	trap cleanup EXIT HUP INT TERM; \
	: > "$$private_root/neutral-probe"; \
	docker run --rm --network none --pull=never \
		--user $(HOST_UID):$(HOST_GID) \
		--volume $(WORKSPACE):/workspace \
		--volume $(CACHE_ROOT):$(CACHE_ROOT) \
		--volume "$$private_root:/isolated-fixture-private" \
		--workdir /workspace \
		--env CI=true \
		--env HOME=$(CACHE_HOME) \
		--env UV_CACHE_DIR=$(UV_CACHE) \
		--env UV_PROJECT_ENVIRONMENT=$(UV_PROJECT_ENVIRONMENT) \
		$(TOOL_IMAGE) uv run --offline colortrace-fixture generate \
		--bundle "$$container_root/runtime-bundle" \
		--oracle /isolated-fixture-private/offline-oracle; \
	test -f "$$private_root/offline-oracle/fixture-oracle.json"; \
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-fixture validate \
		--scenario "$$container_root/runtime-bundle"; \
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-telemetry isolation \
		--report "$$container_root/telemetry-isolation.json"; \
	sed -n '1p' "$$suite_root/telemetry-isolation.json"; \
	sha256sum "$$suite_root/telemetry-isolation.json"; \
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-telemetry no-grafana \
		--scenario "$$container_root/runtime-bundle" \
		--isolation-receipt "$$container_root/telemetry-isolation.json" \
		--report "$$container_root/no-grafana.json"; \
	docker compose --project-name "$$project_name" \
		--file config/telemetry/compose.yaml up --detach --wait; \
	$(TOOL_RUN_HOST) uv run --offline colortrace-telemetry integration \
		--scenario "$$container_root/runtime-bundle" \
		--isolation-receipt "$$container_root/telemetry-isolation.json" \
		--receipt "$$container_root/emission-receipt.json" \
		--report "$$container_root/backend-report.json"; \
	sed -n '1p' "$$suite_root/no-grafana.json"; \
	sha256sum "$$suite_root/no-grafana.json"; \
	sed -n '1p' "$$suite_root/backend-report.json"; \
	sha256sum "$$suite_root/backend-report.json" "$$suite_root/emission-receipt.json"

check-secret:
	@set -eu; \
	scan_root="$$(mktemp -d)"; \
	snapshot_root="$$scan_root/snapshots"; \
	temporary_index="$$scan_root/current.index"; \
	temporary_objects="$$scan_root/objects"; \
	trap 'test -n "$$scan_root" && rm -rf "$$scan_root"' EXIT HUP INT TERM; \
	real_objects="$$(git rev-parse --path-format=absolute --git-path objects)"; \
	mkdir -p "$$snapshot_root/index" "$$snapshot_root/worktree" "$$temporary_objects"; \
	git checkout-index --all --prefix="$$snapshot_root/index/"; \
	GIT_INDEX_FILE="$$temporary_index" \
		GIT_OBJECT_DIRECTORY="$$temporary_objects" \
		GIT_ALTERNATE_OBJECT_DIRECTORIES="$$real_objects" \
		git read-tree HEAD; \
	GIT_INDEX_FILE="$$temporary_index" \
		GIT_OBJECT_DIRECTORY="$$temporary_objects" \
		GIT_ALTERNATE_OBJECT_DIRECTORIES="$$real_objects" \
		git add --all; \
	GIT_INDEX_FILE="$$temporary_index" \
		GIT_OBJECT_DIRECTORY="$$temporary_objects" \
		GIT_ALTERNATE_OBJECT_DIRECTORIES="$$real_objects" \
		git checkout-index \
		--all --prefix="$$snapshot_root/worktree/"; \
	test -f "$$snapshot_root/index/.gitleaks.toml"; \
	test -f "$$snapshot_root/worktree/.gitleaks.toml"; \
	docker run --rm \
		--network none \
		--pull=never \
		--user $(HOST_UID):$(HOST_GID) \
		--volume "$$snapshot_root/index:/source:ro" \
		$(GITLEAKS_IMAGE) dir --no-banner --redact \
		--config /source/.gitleaks.toml /source; \
	docker run --rm \
		--network none \
		--pull=never \
		--user $(HOST_UID):$(HOST_GID) \
		--volume "$$snapshot_root/worktree:/source:ro" \
		$(GITLEAKS_IMAGE) dir --no-banner --redact \
		--config /source/.gitleaks.toml /source; \
	docker run --rm \
		--network none \
		--pull=never \
		--user $(HOST_UID):$(HOST_GID) \
		--volume "$(WORKSPACE):/repo:ro" \
		--volume "$$snapshot_root/index/.gitleaks.toml:/policy/.gitleaks.toml:ro" \
		--workdir /repo \
		$(GITLEAKS_IMAGE) git --no-banner --redact \
		--config /policy/.gitleaks.toml --log-opts=--all

final-image-cleanup:
	@set -eu; \
	candidate="$(SECURITY_CANDIDATE_SHA)"; \
	case "$$candidate" in (*[!0-9a-f]*|'') echo "invalid cleanup candidate" >&2; exit 1;; esac; \
	test "$${#candidate}" -eq 40; \
	image_root="$(WORKSPACE)/.cache/security-images/$$candidate"; \
	case "$$image_root" in ("$(WORKSPACE)/.cache/security-images/"*) ;; (*) exit 1;; esac; \
	runtime_ref="colortrace-security-runtime:$$candidate"; \
	runtime_repro_ref="colortrace-security-runtime-repro:$$candidate"; \
	web_ref="colortrace-security-web:$$candidate"; \
	docker rm --force \
		"colortrace-sbom-runtime-$$candidate" \
		"colortrace-sbom-web-$$candidate" \
		"colortrace-repro-runtime-a-$$candidate" \
		"colortrace-repro-runtime-b-$$candidate" \
		"colortrace-smoke-runtime-$$candidate" \
		"colortrace-smoke-web-$$candidate" >/dev/null 2>&1 || true; \
	docker image rm "$$runtime_ref" "$$runtime_repro_ref" "$$web_ref" >/dev/null 2>&1 || true; \
	rm -rf -- "$$image_root"; \
	if ! docker info >/dev/null 2>&1; then \
		echo "cleanup cannot verify the Docker daemon" >&2; exit 1; \
	fi; \
	cleanup_failed=0; \
	for resource in \
		"colortrace-sbom-runtime-$$candidate" \
		"colortrace-sbom-web-$$candidate" \
		"colortrace-repro-runtime-a-$$candidate" \
		"colortrace-repro-runtime-b-$$candidate" \
		"colortrace-smoke-runtime-$$candidate" \
		"colortrace-smoke-web-$$candidate"; do \
		if docker container inspect "$$resource" >/dev/null 2>&1; then \
			echo "cleanup retained container $$resource" >&2; cleanup_failed=1; \
		fi; \
	done; \
	for resource in "$$runtime_ref" "$$runtime_repro_ref" "$$web_ref"; do \
		if docker image inspect "$$resource" >/dev/null 2>&1; then \
			echo "cleanup retained image $$resource" >&2; cleanup_failed=1; \
		fi; \
	done; \
	if test -e "$$image_root"; then \
		echo "cleanup retained the private image archive directory" >&2; cleanup_failed=1; \
	fi; \
	test "$$cleanup_failed" -eq 0; \
	echo "exact candidate image cleanup verified: $$candidate"

final-image-evidence: prepare-cache
	@set -eu; \
	test "$$(git rev-parse HEAD)" = "$(SECURITY_CANDIDATE_SHA)"; \
	git diff --quiet; \
	git diff --cached --quiet; \
	test -z "$$(git ls-files --others --exclude-standard)"; \
	candidate_tree="$$(git rev-parse HEAD^{tree})"; \
	source_date_epoch="$$(git show -s --format=%ct "$(SECURITY_CANDIDATE_SHA)")"; \
	case "$$source_date_epoch" in (*[!0-9]*|'') echo "invalid source date epoch" >&2; exit 1;; esac; \
	image_root="$(WORKSPACE)/.cache/security-images/$(SECURITY_CANDIDATE_SHA)"; \
	case "$$image_root" in ("$(WORKSPACE)/.cache/security-images/"*) ;; (*) exit 1;; esac; \
	runtime_ref="colortrace-security-runtime:$(SECURITY_CANDIDATE_SHA)"; \
	runtime_repro_ref="colortrace-security-runtime-repro:$(SECURITY_CANDIDATE_SHA)"; \
	web_ref="colortrace-security-web:$(SECURITY_CANDIDATE_SHA)"; \
	cleanup() { \
		$(MAKE) --no-print-directory final-image-cleanup \
			SECURITY_CANDIDATE_SHA="$(SECURITY_CANDIDATE_SHA)" \
			CACHE_ROOT="$(CACHE_ROOT)"; \
	}; \
	finish() { \
		command_status=$$?; \
		trap - EXIT HUP INT TERM; \
		if ! cleanup; then command_status=1; fi; \
		exit "$$command_status"; \
	}; \
	trap finish EXIT; \
	trap 'exit 129' HUP; \
	trap 'exit 130' INT; \
	trap 'exit 143' TERM; \
	cleanup; \
	install -d -m 0700 "$$image_root"; \
	install -d -m 0700 "$$image_root/context"; \
	git archive --format=tar --output "$$image_root/context.tar" HEAD; \
	tar -xf "$$image_root/context.tar" -C "$$image_root/context"; \
	rm "$$image_root/context.tar"; \
	docker buildx build --pull=false --provenance=false --no-cache-filter mcp-grafana \
		--file "$$image_root/context/containers/Dockerfile.runtime" --target runtime \
		--build-arg SOURCE_COMMIT="$(SECURITY_CANDIDATE_SHA)" \
		--build-arg SOURCE_TREE="$$candidate_tree" \
		--build-arg SOURCE_DATE_EPOCH="$$source_date_epoch" \
		--output "type=docker,dest=$$image_root/runtime.tar,rewrite-timestamp=true" \
		--tag "$$runtime_ref" \
		"$$image_root/context"; \
	chmod 0600 "$$image_root/runtime.tar"; \
	docker load --input "$$image_root/runtime.tar" >/dev/null; \
	docker buildx build --pull=false --provenance=false --no-cache-filter mcp-grafana \
		--file "$$image_root/context/containers/Dockerfile.runtime" --target runtime \
		--build-arg SOURCE_COMMIT="$(SECURITY_CANDIDATE_SHA)" \
		--build-arg SOURCE_TREE="$$candidate_tree" \
		--build-arg SOURCE_DATE_EPOCH="$$source_date_epoch" \
		--output "type=docker,dest=$$image_root/runtime-repro.tar,rewrite-timestamp=true" \
		--tag "$$runtime_repro_ref" \
		"$$image_root/context"; \
	chmod 0600 "$$image_root/runtime-repro.tar"; \
	docker load --input "$$image_root/runtime-repro.tar" >/dev/null; \
	docker create --name "colortrace-repro-runtime-a-$(SECURITY_CANDIDATE_SHA)" \
		"$$runtime_ref" >/dev/null; \
	docker cp "colortrace-repro-runtime-a-$(SECURITY_CANDIDATE_SHA):/usr/local/bin/mcp-grafana" \
		"$$image_root/mcp-grafana-a"; \
	docker rm "colortrace-repro-runtime-a-$(SECURITY_CANDIDATE_SHA)" >/dev/null; \
	docker create --name "colortrace-repro-runtime-b-$(SECURITY_CANDIDATE_SHA)" \
		"$$runtime_repro_ref" >/dev/null; \
	docker cp "colortrace-repro-runtime-b-$(SECURITY_CANDIDATE_SHA):/usr/local/bin/mcp-grafana" \
		"$$image_root/mcp-grafana-b"; \
	docker rm "colortrace-repro-runtime-b-$(SECURITY_CANDIDATE_SHA)" >/dev/null; \
	chmod 0600 "$$image_root/mcp-grafana-a" "$$image_root/mcp-grafana-b"; \
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo mcp-build-evidence \
		--output "$(SECURITY_EVIDENCE_CONTAINER)/mcp-grafana-reproducibility.json" \
		--candidate-sha "$(SECURITY_CANDIDATE_SHA)" \
		--candidate-tree "$$candidate_tree" \
		--first-binary "/workspace/.cache/security-images/$(SECURITY_CANDIDATE_SHA)/mcp-grafana-a" \
		--second-binary "/workspace/.cache/security-images/$(SECURITY_CANDIDATE_SHA)/mcp-grafana-b" \
		--first-archive "/workspace/.cache/security-images/$(SECURITY_CANDIDATE_SHA)/runtime.tar" \
		--second-archive "/workspace/.cache/security-images/$(SECURITY_CANDIDATE_SHA)/runtime-repro.tar" \
		--first-reference "$$runtime_ref" \
		--second-reference "$$runtime_repro_ref"; \
	docker buildx build --pull=false --provenance=false \
		--file "$$image_root/context/containers/Dockerfile.web" \
		--build-arg SOURCE_COMMIT="$(SECURITY_CANDIDATE_SHA)" \
		--build-arg SOURCE_TREE="$$candidate_tree" \
		--build-arg SOURCE_DATE_EPOCH="$$source_date_epoch" \
		--output "type=docker,dest=$$image_root/web.tar,rewrite-timestamp=true" \
		--tag "$$web_ref" \
		"$$image_root/context"; \
	chmod 0600 "$$image_root/web.tar"; \
	docker load --input "$$image_root/web.tar" >/dev/null; \
	capture() { \
		name="$$1"; reference="$$2"; \
		archive="$$image_root/$$name.tar"; \
		bundle="$(SECURITY_EVIDENCE_HOST)/images/$$name/bundle"; \
		container="colortrace-sbom-$$name-$(SECURITY_CANDIDATE_SHA)"; \
		install -d -m 0700 "$$bundle"; \
		test -s "$$archive"; \
		docker create --name "$$container" "$$reference" >/dev/null; \
		docker cp "$$container:/usr/share/colortrace/licenses/." "$$bundle"; \
		chmod -R u+rwX,go-rwx "$$bundle"; \
		if test "$$name" = web; then \
			docker export "$$container" | tar -tf - > "$$image_root/web-rootfs-paths"; \
			if grep -i yarn "$$image_root/web-rootfs-paths"; then \
				echo "Yarn remains in the exported web rootfs" >&2; exit 1; \
			fi; \
		fi; \
		docker rm "$$container" >/dev/null; \
		docker run --rm --network none --pull=never \
			--user $(HOST_UID):$(HOST_GID) \
			--volume "$$archive:/image.tar:ro" \
			--volume "$(WORKSPACE)/.cache/trivy:/trivy-cache" \
			--volume "$(SECURITY_EVIDENCE_HOST):/evidence" \
			$(TRIVY_IMAGE) image --cache-dir /trivy-cache --offline-scan \
				--skip-db-update --skip-java-db-update --skip-version-check \
				--format cyclonedx --output "/evidence/images/$$name/raw-sbom.cdx.json" \
				--input /image.tar; \
		docker run --rm --network none --pull=never \
			--user $(HOST_UID):$(HOST_GID) \
			--volume "$(WORKSPACE)/.cache/trivy:/trivy-cache" \
			--volume "$(SECURITY_EVIDENCE_HOST):/evidence" \
			$(TRIVY_IMAGE) sbom --cache-dir /trivy-cache --offline-scan \
				--scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
				--skip-db-update --skip-java-db-update --skip-version-check \
				--format json --output "/evidence/images/$$name/vulnerability.json" \
				"/evidence/images/$$name/raw-sbom.cdx.json"; \
	}; \
	capture runtime "$$runtime_ref"; \
	docker run --rm --name "colortrace-smoke-runtime-$(SECURITY_CANDIDATE_SHA)" \
		--network none --pull=never \
		--entrypoint /opt/colortrace/bin/python "$$runtime_ref" \
		-c 'import os; assert os.geteuid() != 0; import colortrace_api'; \
	capture web "$$web_ref"; \
	docker run --rm --name "colortrace-smoke-web-$(SECURITY_CANDIDATE_SHA)" \
		--network none --pull=never --entrypoint node "$$web_ref" \
		-e 'if (process.getuid() === 0) process.exit(1)'; \
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo image-evidence \
		--output "$(SECURITY_EVIDENCE_CONTAINER)" \
		--candidate-sha "$(SECURITY_CANDIDATE_SHA)" \
		--candidate-tree "$$candidate_tree" \
		--scanner-image "$(TRIVY_IMAGE)" \
		--runtime-archive "/workspace/.cache/security-images/$(SECURITY_CANDIDATE_SHA)/runtime.tar" \
		--runtime-bundle "$(SECURITY_EVIDENCE_CONTAINER)/images/runtime/bundle" \
		--runtime-sbom "$(SECURITY_EVIDENCE_CONTAINER)/images/runtime/raw-sbom.cdx.json" \
		--runtime-reference "$$runtime_ref" \
		--web-archive "/workspace/.cache/security-images/$(SECURITY_CANDIDATE_SHA)/web.tar" \
		--web-bundle "$(SECURITY_EVIDENCE_CONTAINER)/images/web/bundle" \
		--web-sbom "$(SECURITY_EVIDENCE_CONTAINER)/images/web/raw-sbom.cdx.json" \
		--web-reference "$$web_ref"

security-evidence: prepare-cache
	@set -eu; \
	test "$$(git rev-parse HEAD)" = "$(SECURITY_CANDIDATE_SHA)"; \
	git diff --quiet; \
	git diff --cached --quiet; \
	test -z "$$(git ls-files --others --exclude-standard)"; \
	mkdir -p "$(SECURITY_EVIDENCE_HOST)" "$(WORKSPACE)/.cache/trivy"; \
	docker run --rm --network none --pull=never \
		--user $(HOST_UID):$(HOST_GID) \
		--volume $(WORKSPACE):/workspace \
		--volume $(CACHE_ROOT):$(CACHE_ROOT) \
		--workdir /workspace \
		--env CI=true \
		--env HOME=$(CACHE_HOME) \
		--env UV_CACHE_DIR=$(UV_CACHE) \
		--env UV_PROJECT_ENVIRONMENT=$(UV_PROJECT_ENVIRONMENT) \
		--env COLORTRACE_CI=$(GITHUB_ACTIONS) \
		--env COLORTRACE_DOCKER_ENDPOINT=$(DOCKER_HOST) \
		--env COLORTRACE_HOST_DOCKER_SOCKET_PRESENT=$$(test -S /var/run/docker.sock && echo true || echo false) \
		--env COLORTRACE_RUNNER_ARCH=$(RUNNER_ARCH) \
		--env "COLORTRACE_RUNNER_ENVIRONMENT=$(RUNNER_ENVIRONMENT)" \
		--env "COLORTRACE_RUNNER_NAME=$(RUNNER_NAME)" \
		--env COLORTRACE_RUNNER_OS=$(RUNNER_OS) \
		$(TOOL_IMAGE) uv run --offline colortrace-repo security-prepare \
			--output "$(SECURITY_EVIDENCE_CONTAINER)"; \
	$(MAKE) check-secret; \
	docker run --rm --network none --pull=never \
		--user $(HOST_UID):$(HOST_GID) \
		--volume $(WORKSPACE):/source:ro \
		--volume "$(SECURITY_EVIDENCE_HOST):/evidence" \
		--workdir /source \
		$(GITLEAKS_IMAGE) git --no-banner --redact \
			--config /source/.gitleaks.toml \
			--report-format json --report-path /evidence/secret.json \
			--log-opts=HEAD; \
	docker run --rm --pull=never \
		--user $(HOST_UID):$(HOST_GID) \
		--volume $(WORKSPACE):/workspace:ro \
		--volume "$(SECURITY_EVIDENCE_HOST):/evidence" \
		--volume "$(WORKSPACE)/.cache/trivy:/trivy-cache" \
		$(TRIVY_IMAGE) sbom --cache-dir /trivy-cache \
			--scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
			--ignorefile /workspace/policy/trivyignore.yaml \
			--skip-java-db-update --skip-version-check \
			--format json --output /evidence/vulnerability.json \
			/evidence/sbom.cdx.json; \
	case "$(SECURITY_REQUIRE_IMAGES)" in \
		(true) $(MAKE) final-image-evidence \
			SECURITY_CANDIDATE_SHA="$(SECURITY_CANDIDATE_SHA)" \
			CACHE_ROOT="$(CACHE_ROOT)"; image_requirement=--require-images ;; \
		(false) image_requirement= ;; \
		(*) echo "SECURITY_REQUIRE_IMAGES must be true or false" >&2; exit 1 ;; \
	esac; \
	scanner_metadata="$$(docker run --rm --network none --pull=never \
		--user $(HOST_UID):$(HOST_GID) \
		--volume "$(WORKSPACE)/.cache/trivy:/trivy-cache:ro" \
		$(TRIVY_IMAGE) --cache-dir /trivy-cache version --format json)"; \
	candidate_tree="$$(git rev-parse HEAD^{tree})"; \
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo security-finalize \
		--output "$(SECURITY_EVIDENCE_CONTAINER)" \
		--candidate-sha "$(SECURITY_CANDIDATE_SHA)" \
		--candidate-tree "$$candidate_tree" \
		--scanner-image "$(TRIVY_IMAGE)" \
		--scanner-metadata "$$scanner_metadata" \
		--secret-scanner-image "$(GITLEAKS_IMAGE)" \
		$$image_requirement

check-secret-fixture:
	@set -eu; \
	fixture_root="$$(mktemp -d)"; \
	trap 'test -n "$$fixture_root" && rm -rf "$$fixture_root"' EXIT HUP INT TERM; \
	cp Makefile .gitleaks.toml "$$fixture_root/"; \
	git -C "$$fixture_root" init --quiet; \
	git -C "$$fixture_root" config user.email fixture@invalid; \
	git -C "$$fixture_root" config user.name fixture; \
	git -C "$$fixture_root" add Makefile .gitleaks.toml; \
	git -C "$$fixture_root" commit --quiet --message baseline; \
	$(MAKE) --silent --directory "$$fixture_root" check-secret >/dev/null; \
	token_value="$$(printf '%s%s%s' 'ct_' 'test_' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')"; \
	printf 'SYNTHETIC_TOKEN=%s\n' "$$token_value" > "$$fixture_root/fixture.env"; \
	git -C "$$fixture_root" add fixture.env; \
	printf 'SYNTHETIC_TOKEN=safe\n' > "$$fixture_root/fixture.env"; \
	printf "\n[allowlist]\npaths = ['fixture[.]env$$']\n" >> "$$fixture_root/.gitleaks.toml"; \
	if $(MAKE) --silent --directory "$$fixture_root" check-secret >/dev/null 2>&1; then \
		echo "staged secret fixture was not rejected" >&2; \
		exit 1; \
	fi

check-fast: check-format check-lint check-typecheck check-unit check-contract check-generated check-license check-wheel-license check-policy check-secret-fixture check-terraform

check: check-fast check-telemetry check-secret

check-bootstrap:
	@tmp_dir="$$(mktemp -d)"; \
	trap 'test -n "$$tmp_dir" && rm -rf "$$tmp_dir"' EXIT HUP INT TERM; \
	git clone --quiet --local --no-hardlinks "$(WORKSPACE)" "$$tmp_dir/repository"; \
	$(MAKE) --directory "$$tmp_dir/repository" bootstrap check
