SHELL := /bin/sh

TOOL_IMAGE := colortrace-dev:phase1
GITLEAKS_IMAGE := zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
TELEMETRY_IMAGE := grafana/otel-lgtm@sha256:bb182ac3174a20923fa58f00d1790fa71eb06cc0150078c0b0e8feb9e6611492
HOST_UID := $(shell id -u)
HOST_GID := $(shell id -g)
WORKSPACE := $(CURDIR)
CACHE_HOME := $(WORKSPACE)/.cache/home

TOOL_RUN := docker run --rm \
	--user $(HOST_UID):$(HOST_GID) \
	--volume $(WORKSPACE):/workspace \
	--workdir /workspace \
	--env CI=true \
	--env HOME=/workspace/.cache/home \
	--env UV_CACHE_DIR=/workspace/.cache/uv \
	$(TOOL_IMAGE)

TOOL_RUN_OFFLINE := docker run --rm \
	--network none \
	--pull=never \
	--user $(HOST_UID):$(HOST_GID) \
	--volume $(WORKSPACE):/workspace \
	--workdir /workspace \
	--env CI=true \
	--env HOME=/workspace/.cache/home \
	--env UV_CACHE_DIR=/workspace/.cache/uv \
	$(TOOL_IMAGE)

TOOL_RUN_HOST := docker run --rm \
	--network host \
	--pull=never \
	--user $(HOST_UID):$(HOST_GID) \
	--volume $(WORKSPACE):/workspace \
	--workdir /workspace \
	--env CI=true \
	--env HOME=/workspace/.cache/home \
	--env UV_CACHE_DIR=/workspace/.cache/uv \
	$(TOOL_IMAGE)

.PHONY: bootstrap build-tools prepare-cache format generate generate-fixture check check-fast \
	check-format check-lint check-typecheck check-unit check-contract \
	check-generated check-license check-policy check-secret check-secret-fixture check-telemetry \
	check-bootstrap

prepare-cache:
	@mkdir -p "$(CACHE_HOME)" "$(WORKSPACE)/.cache/uv" "$(WORKSPACE)/.cache/pnpm"

build-tools:
	docker build --pull --file Dockerfile.dev --tag $(TOOL_IMAGE) .
	docker pull $(GITLEAKS_IMAGE)
	docker pull $(TELEMETRY_IMAGE)

bootstrap: prepare-cache build-tools
	$(TOOL_RUN) uv sync --locked --all-groups --all-packages
	$(TOOL_RUN) pnpm install --frozen-lockfile --store-dir /workspace/.cache/pnpm

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
	$(TOOL_RUN_OFFLINE) uv run --offline pytest
	$(TOOL_RUN_OFFLINE) pnpm run test

check-contract: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo contracts

check-generated: prepare-cache
	$(TOOL_RUN_OFFLINE) pnpm run generate:check
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo generated

check-license: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo dependencies

check-policy: prepare-cache
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo ai-policy
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo actions
	$(TOOL_RUN_OFFLINE) uv run --offline colortrace-repo binary-assets

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
		--volume "$$private_root:/isolated-fixture-private" \
		--workdir /workspace \
		--env CI=true \
		--env HOME=/workspace/.cache/home \
		--env UV_CACHE_DIR=/workspace/.cache/uv \
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

check-fast: check-format check-lint check-typecheck check-unit check-contract check-generated check-license check-policy check-secret-fixture

check: check-fast check-telemetry check-secret

check-bootstrap:
	@tmp_dir="$$(mktemp -d)"; \
	trap 'test -n "$$tmp_dir" && rm -rf "$$tmp_dir"' EXIT HUP INT TERM; \
	git clone --quiet --local --no-hardlinks "$(WORKSPACE)" "$$tmp_dir/repository"; \
	$(MAKE) --directory "$$tmp_dir/repository" bootstrap check
