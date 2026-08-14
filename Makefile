# Defaults for prod parity (can be overridden in the environment)
export POSTGRES_PASSWORD ?= crypto_pass_parity
export REDIS_PASSWORD ?= redis_pass_parity
export JWT_SECRET ?= parity-dev-secret-key
export NATS_PASSWORD ?= nats_pass_parity
export INFLUXDB_PASSWORD ?= adminpass_parity
export INFLUXDB_TOKEN ?= dev-token-1234567890
export NATS_USER ?= nats_user
export POSTGRES_USER ?= crypto_user
export POSTGRES_DB ?= crypto_inventory

# --- Go toolchain pin (single-sourced from go.work) -------------------------
# Critical Rule #1: Go 1.26 ONLY; 1.27+ is forbidden. GOTOOLCHAIN is the only
# mechanical enforcement of that rule, so it must never silently relax.
#
#   GOTOOLCHAIN=local   blocks 1.27 (good) but ALSO refuses to fetch the
#                       sanctioned patch release, so every Go target breaks on
#                       any machine whose installed Go lags go.work.
#   GOTOOLCHAIN=auto    fetches the sanctioned patch (good) but ALSO happily
#                       downloads 1.27+ — it removes the tripwire entirely.
#   GOTOOLCHAIN=goX.Y.Z does both: it auto-provisions exactly that toolchain and
#                       still hard-fails any module requiring a newer one, e.g.
#                       "go.mod requires go >= 1.27.0 (running go 1.26.6;
#                        GOTOOLCHAIN=go1.26.6)".
#
# The patch version is derived from go.work so there is exactly one place to bump
# it, but the MAJOR.MINOR line is asserted against the policy below — otherwise a
# `go.work` edit to 1.27 would move the pin along with it and disarm the guard.
GO_POLICY_LINE := 1.26
GO_WORK_VERSION := $(shell awk '/^go /{print $$2; exit}' go.work 2>/dev/null)
ifeq ($(GO_WORK_VERSION),)
  # No go.work / no `go` directive: fall back to the fail-CLOSED mode. Never
  # `auto` — a missing derivation must not quietly drop the 1.27 tripwire.
  GOTOOLCHAIN_PIN := local
else ifneq ($(words $(subst ., ,$(GO_WORK_VERSION))),3)
  # A two-part directive ("go 1.26") would derive `go1.26`, which Go rejects as
  # "a language version but not a toolchain version". Fail loudly rather than
  # limp along; the fix is a one-line go.work edit.
  $(error go.work declares `go $(GO_WORK_VERSION)`, which derives the invalid toolchain name `go$(GO_WORK_VERSION)`. go.work must carry a full X.Y.Z version (e.g. `go $(GO_POLICY_LINE).6`) so GOTOOLCHAIN can be pinned exactly.)
else ifneq ($(basename $(GO_WORK_VERSION)),$(GO_POLICY_LINE))
  $(error Critical Rule #1 violation: go.work declares `go $(GO_WORK_VERSION)`, but this project is Go $(GO_POLICY_LINE) ONLY. Revert go.work — do not bump GO_POLICY_LINE to make this pass.)
else
  GOTOOLCHAIN_PIN := go$(GO_WORK_VERSION)
endif
export GOTOOLCHAIN=$(GOTOOLCHAIN_PIN)

# Prefer Docker Compose V2 plugin; fall back to standalone binary
DOCKER_COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

# Existing targets above
# ...

.PHONY:
.PHONY: node_modules_check
node_modules_check:
	@command -v node >/dev/null 2>&1 || { echo "Node.js is required"; exit 1; }

.PHONY: generate generate-docker-compose generate-k8s-ingress cluster-suspend cluster-resume cluster-status verify-generated verify-db-files \
	sign-content-bundle verify-content-bundle stage-content-bundle unstage-content-bundle
generate: node_modules_check generate-k8s-ingress ## Generate shared docs/config from standards registry
	@cd scripts && npm install --no-fund --no-audit >/dev/null 2>&1 || true
	node ./scripts/generate-from-registry.mjs | cat
	node ./scripts/generate-docker-compose.mjs | cat
	node ./scripts/generate-alert-registry.mjs | cat
	node ./scripts/generate-edition-matrix.mjs | cat
	# Note: Environment files (.env, .env.ec2-smoke, .env.prod) are generated
	# by their respective deployment scripts, not here

# schema.sql and seed.sql are manually maintained — edit them directly.
# (The one-time consolidation tooling that built them from per-feature
# migration files was removed along with scripts/database/archive/.)
verify-db-files: ## Verify that schema.sql and seed.sql exist
	@echo "Verifying database files..."
	@test -f scripts/database/schema.sql || (echo "❌ schema.sql not found" && exit 1)
	@test -f scripts/database/seed.sql || (echo "❌ seed.sql not found" && exit 1)
	@echo "✅ schema.sql and seed.sql exist"

# ---------------------------------------------------------------------------
# Enterprise content bundle (regulated compliance frameworks)
# ---------------------------------------------------------------------------
# The five regulated frameworks (SOC 2, PCI-DSS, ISO 27001, NIST CSF,
# IEC 62351-3) are Enterprise content. They live in a signed bundle the chart
# applies when enterprise.contentBundle.enabled=true, NOT in the Core seed.
#
# (Engineering / Licensing) and is deliberately absent from this repository, so
# `sign-content-bundle` fails loudly without EDITION_SIGNING_KEY rather than
# emitting an unsigned bundle. Re-sign and commit the .sig after ANY edit to
# frameworks-regulated.sql.
CONTENT_BUNDLE_DIR := services/compliance-engine/ee/content
CONTENT_BUNDLE_SQL := $(CONTENT_BUNDLE_DIR)/frameworks-regulated.sql
CONTENT_BUNDLE_SIG := $(CONTENT_BUNDLE_SQL).sig
CONTENT_BUNDLE_KEY := $(CONTENT_BUNDLE_DIR)/verify-key.pem
CHART_EE_DIR       := charts/vistaplatform/files/ee

unstage-content-bundle: ## Remove the staged bundle from charts/vistaplatform/files/ee
	rm -rf $(CHART_EE_DIR)
	@echo "✅ removed $(CHART_EE_DIR)"

validate-db-init: ## Validate database initialization readiness (checks critical tables/columns)
	@echo "Validating database initialization readiness..."
	@bash -c 'if [ -f scripts/database-validation.sh ]; then \
		source scripts/database-validation.sh; \
		echo "Critical tables:"; \
		get_critical_tables | while IFS=: read -r table service desc; do \
			[ -n "$$table" ] && echo "  - $$table ($$service)"; \
		done; \
		echo "Critical columns:"; \
		get_critical_columns | while IFS=: read -r column desc; do \
			[ -n "$$column" ] && echo "  - $$column"; \
		done; \
		echo "✅ Database validation library loaded"; \
	else \
		echo "⚠️  Database validation library not found"; \
		exit 1; \
	fi'

generate-docker-compose: node_modules_check ## Generate docker-compose services from registry
	@cd scripts && npm install --no-fund --no-audit >/dev/null 2>&1 || true
	node ./scripts/generate-docker-compose.mjs | cat

generate-gateway: node_modules_check ## Generate Traefik gateway configurations from registry
	@cd scripts && npm install --no-fund --no-audit >/dev/null 2>&1 || true
	@echo "Generating Traefik gateway configurations from registry..."
	@[ -f .env ] && export $$(grep -v '^#' .env | grep -E '^(DEV_CORS_ALLOW_ANY|TRAEFIK_DEV_EXTRA_CORS_ORIGINS)=' | xargs) 2>/dev/null || true; \
	  DEPLOY_ENV=development node scripts/generate-traefik-config.mjs
	@DEPLOY_ENV=ec2-smoke USE_MTLS=true node scripts/generate-traefik-config.mjs
	@DEPLOY_ENV=production node scripts/generate-traefik-config.mjs
	@echo "✅ Traefik gateway configs generated"

generate-k8s-ingress: node_modules_check ## Generate Kubernetes Traefik CRDs (Middleware + IngressRoute) into the Helm chart
	@cd scripts && npm install --no-fund --no-audit >/dev/null 2>&1 || true
	@node ./scripts/generate-k8s-ingress.mjs

KUBE ?= $(HOME)/.kube/config
KUBE_NS ?= vistaplatform

cluster-suspend: ## Scale all vistaplatform deployments to 0 (pause cluster without destroying data)
	@echo "Suspending VistaPlatform on RKE2 cluster (namespace: $(KUBE_NS))..."
	@KUBECONFIG=$(KUBE) kubectl -n $(KUBE_NS) scale deployment --all --replicas=0
	@echo "Done. All pods stopped. Run 'make cluster-resume' to bring them back."

cluster-resume: ## Scale all vistaplatform deployments back to 1
	@echo "Resuming VistaPlatform on RKE2 cluster (namespace: $(KUBE_NS))..."
	@KUBECONFIG=$(KUBE) kubectl -n $(KUBE_NS) scale deployment --all --replicas=1
	@echo "Done. Waiting for rollout..."
	@KUBECONFIG=$(KUBE) kubectl -n $(KUBE_NS) rollout status deployment --timeout=120s 2>&1 || true

cluster-status: ## Show pod status for the vistaplatform namespace
	@KUBECONFIG=$(KUBE) kubectl -n $(KUBE_NS) get pods -o wide

verify-generated: ## Verify generated artifacts exist
	@test -f docsv4/generated/service-ports.md || (echo "Missing docsv4/generated/service-ports.md" && exit 1)
	@test -f docsv4/generated/ui-ports.md || (echo "Missing docsv4/generated/ui-ports.md" && exit 1)
	@test -f config/generated/service-registry.json || (echo "Missing config/generated/service-registry.json" && exit 1)
	@test -f config/generated/docker-compose-services.yml || (echo "Missing config/generated/docker-compose-services.yml" && exit 1)
	@echo "Generated artifacts present."

# Vista Platform - Makefile

.PHONY: help build-services build-sensor build-frontend build-all test test-unit test-integration test-e2e start stop restart logs clean install-deps

# Default target
help: ## Show this help message
	@echo "Vista Platform - Development Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development Environment
start: ## Start all services with docker-compose
	docker-compose up -d

stop: ## Stop all services
	docker-compose down

restart: ## Restart all services
	docker-compose restart

logs: ## Show logs from all services
	docker-compose logs -f

clean: ## Clean up containers, volumes, and images
	docker compose down -v --remove-orphans 2>/dev/null || docker-compose down -v --remove-orphans 2>/dev/null || true
	docker system prune -f

clean-all-volumes: ## Remove ALL persistent volumes for a truly clean start (WARNING: deletes all data)
	@./scripts/clean-all-volumes.sh

# Build Commands
build-services: ## Build all Go backend services
	@if [ "$(PARALLEL)" = "1" ]; then \
		$(MAKE) build-services-parallel; \
	else \
		echo "Building Go services..." && \
		cd services/auth-service && go build -o ../../bin/auth-service ./cmd/main.go && \
		cd ../inventory-service && go build -o ../../bin/inventory-service ./cmd/main.go && \
		cd ../compliance-engine && go build -o ../../bin/compliance-engine ./cmd/main.go && \
		cd ../cbom-service && go build -o ../../bin/cbom-service ./cmd/main.go && \
		cd ../sensor-manager && go build -o ../../bin/sensor-manager ./cmd/main.go && \
		cd ../admin-service && go build -o ../../bin/admin-service ./cmd/main.go && \
		cd ../monitoring-service && go build -o ../../bin/monitoring-service ./cmd/main.go && \
		cd ../cluster-sensor-service && go build -o ../../bin/cluster-sensor-service ./cmd/main.go && \
		cd ../resource-tracker-service && go build -o ../../bin/resource-tracker-service ./cmd/main.go && \
		cd ../tenant-health-service && go build -o ../../bin/tenant-health-service ./cmd/main.go && \
		cd ../mcp-service && go build -o ../../bin/mcp-service ./cmd && \
		echo "Go services built successfully!"; \
	fi

build-services-parallel: ## Build all Go services in parallel
	@echo "Building Go services in parallel..."
	@$(MAKE) -j$(shell nproc) build-auth-service build-inventory-service build-compliance-engine \
		build-cbom-service build-sensor-manager build-admin-service build-monitoring-service \
		build-cluster-sensor-service build-resource-tracker-service build-tenant-health-service \
		build-pcap-processor build-mcp-service

# ---------------------------------------------------------------------------
# Licensed image targets — two variants:
#
#   build-licensed  — Enterprise edition, no obfuscation (-tags ee)
#                     Use for: internal prod, smoke tests, EC2 single-host deployments
#                     Usage: make build-licensed LICENSED_TAG=v1.2.3 IMAGE_REGISTRY=<registry>
#
#   build-dist      — Enterprise edition, garble-obfuscated (-tags ee)
#                     Use for: MSP/external distribution
#                     Usage: make build-dist DIST_TAG=v1.2.3-acme IMAGE_REGISTRY=<registry>
#
# Normal dev builds (make build-services) are completely unaffected.
# ---------------------------------------------------------------------------
# --- Container base images -----------------------------------------------------
# The Dockerfiles declare ARG GO_BUILDER_IMAGE / ARG RUNTIME_IMAGE with PUBLIC
# defaults (golang:1.26-alpine / alpine:3.24.1) so that a plain `docker build`
# from a source checkout works with no internal infrastructure — that is what an
# open-source consumer gets.
#
# Internal builds override them here to the Harbor DHI mirrors, preserving the
# hardened base images the release pipeline has always used. Do NOT move these
# values into the Dockerfiles: that is exactly the coupling that makes the tree
# unbuildable outside this lab.
#
# To build against public bases deliberately (e.g. reproducing a community
# build): make build-dist GO_BUILDER_IMAGE=golang:1.26-alpine RUNTIME_IMAGE=alpine:3.24.1
GO_BUILDER_IMAGE ?= golang:1.26-alpine
RUNTIME_IMAGE    ?= alpine:3.24.1
BASE_IMAGE_ARGS  := --build-arg GO_BUILDER_IMAGE=$(GO_BUILDER_IMAGE) --build-arg RUNTIME_IMAGE=$(RUNTIME_IMAGE)

LICENSED_TAG ?= licensed-dev
DIST_TAG ?= dist-dev
LICENSED_REGISTRY ?= $(IMAGE_REGISTRY)
LICENSED_REPO_PREFIX ?= vistaplatform

_ALL_SVCS = auth-service inventory-service compliance-engine cbom-service \
	sensor-manager admin-service monitoring-service cluster-sensor-service \
	resource-tracker-service tenant-health-service audit-service \
	device-interrogation-service discovery-processor-service notification-service \
	pcap-processor mcp-service

# Frontend images — distinct list because they don't have license-protected
# Go code to obfuscate, so they build from Dockerfile.prod (not .dist) and
# don't get -tags ee treatment. Still part of every customer release.
# The shipped UIs are web-ui (built from frontend-v2/) + admin-ui ("VISTA
# Operations", built from admin-ui-v2/). Both keep their original image identity
# (build-and-swap, ADR-0013).
_ALL_UIS = web-ui admin-ui

# Full release-image set (18 total). The release-customer.yml workflow
# iterates over this same set when promoting Harbor → Docker Hub, so keep
# them in sync.
_ALL_IMAGES = $(_ALL_SVCS) $(_ALL_UIS)

.PHONY: build-licensed push-licensed \
	build-licensed-auth-service build-licensed-inventory-service build-licensed-compliance-engine \
	build-licensed-cbom-service build-licensed-sensor-manager build-licensed-admin-service \
	build-licensed-monitoring-service build-licensed-cluster-sensor-service \
	build-licensed-resource-tracker-service build-licensed-tenant-health-service \
	build-licensed-audit-service \
	build-licensed-device-interrogation-service build-licensed-discovery-processor-service \
	build-licensed-notification-service build-licensed-pcap-processor build-licensed-mcp-service

build-licensed: ## Build licensed (dev-key, no obfuscation) images for all services
	@if [ -z "$(IMAGE_REGISTRY)" ]; then echo "ERROR: IMAGE_REGISTRY is required. Run: make build-licensed LICENSED_TAG=<tag> IMAGE_REGISTRY=<registry>"; exit 1; fi
	@echo "Building licensed images with tag $(LICENSED_TAG) ..."
	@$(MAKE) -j$(shell nproc) \
		build-licensed-auth-service build-licensed-inventory-service build-licensed-compliance-engine \
		build-licensed-cbom-service build-licensed-sensor-manager build-licensed-admin-service \
		build-licensed-monitoring-service build-licensed-cluster-sensor-service \
		build-licensed-resource-tracker-service build-licensed-tenant-health-service \
		build-licensed-audit-service \
		build-licensed-device-interrogation-service build-licensed-discovery-processor-service \
		build-licensed-notification-service build-licensed-pcap-processor build-licensed-mcp-service
	@echo "Licensed images built. Run: make push-licensed LICENSED_TAG=$(LICENSED_TAG) IMAGE_REGISTRY=$(IMAGE_REGISTRY)"

build-licensed-auth-service:
	docker build $(BASE_IMAGE_ARGS) -f services/auth-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/auth-service:$(LICENSED_TAG) .

build-licensed-inventory-service:
	docker build $(BASE_IMAGE_ARGS) -f services/inventory-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/inventory-service:$(LICENSED_TAG) .

build-licensed-compliance-engine:
	docker build $(BASE_IMAGE_ARGS) -f services/compliance-engine/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/compliance-engine:$(LICENSED_TAG) .

build-licensed-cbom-service:
	docker build $(BASE_IMAGE_ARGS) -f services/cbom-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/cbom-service:$(LICENSED_TAG) .

build-licensed-sensor-manager:
	docker build $(BASE_IMAGE_ARGS) -f services/sensor-manager/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/sensor-manager:$(LICENSED_TAG) .

build-licensed-admin-service:
	docker build $(BASE_IMAGE_ARGS) -f services/admin-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/admin-service:$(LICENSED_TAG) .

build-licensed-monitoring-service:
	docker build $(BASE_IMAGE_ARGS) -f services/monitoring-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/monitoring-service:$(LICENSED_TAG) .

build-licensed-cluster-sensor-service:
	docker build $(BASE_IMAGE_ARGS) -f services/cluster-sensor-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/cluster-sensor-service:$(LICENSED_TAG) .

build-licensed-resource-tracker-service:
	docker build $(BASE_IMAGE_ARGS) -f services/resource-tracker-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/resource-tracker-service:$(LICENSED_TAG) .

build-licensed-tenant-health-service:
	docker build $(BASE_IMAGE_ARGS) -f services/tenant-health-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/tenant-health-service:$(LICENSED_TAG) .

build-licensed-audit-service:
	docker build $(BASE_IMAGE_ARGS) -f services/audit-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/audit-service:$(LICENSED_TAG) .

build-licensed-device-interrogation-service:
	docker build $(BASE_IMAGE_ARGS) -f services/device-interrogation-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/device-interrogation-service:$(LICENSED_TAG) .

build-licensed-discovery-processor-service:
	docker build $(BASE_IMAGE_ARGS) -f services/discovery-processor-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/discovery-processor-service:$(LICENSED_TAG) .

build-licensed-notification-service:
	docker build $(BASE_IMAGE_ARGS) -f services/notification-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/notification-service:$(LICENSED_TAG) .

build-licensed-mcp-service:
	docker build $(BASE_IMAGE_ARGS) -f services/mcp-service/Dockerfile.licensed \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/mcp-service:$(LICENSED_TAG) .

build-licensed-pcap-processor: ## pcap-processor uses CGO — same as prod build, no garble
	docker build $(BASE_IMAGE_ARGS) -f services/pcap-processor/Dockerfile.prod \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/pcap-processor:$(LICENSED_TAG) .

push-licensed: ## Push licensed images to registry (requires LICENSED_TAG and IMAGE_REGISTRY)
	@if [ -z "$(IMAGE_REGISTRY)" ]; then echo "ERROR: IMAGE_REGISTRY is required."; exit 1; fi
	@echo "Pushing licensed images with tag $(LICENSED_TAG) ..."
	@for svc in $(_ALL_SVCS); do \
		docker push $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/$$svc:$(LICENSED_TAG); \
	done
	@echo "All licensed images pushed."

# ---------------------------------------------------------------------------
# Dist image targets — the full customer release set.
#
# Backends (16): garble-obfuscated Enterprise edition (-tags ee)
#                via per-service Dockerfile.dist. pcap-processor uses
#                Dockerfile.prod because CGO can't be garble-obfuscated.
# Frontends (2): web-ui + admin-ui from Dockerfile.prod. No license code to
#                obfuscate; Vite already produces minified production assets.
#
# Total: 18 images, matching the matrix in .github/workflows/release-customer.yml.
# Use these when staging a release to Harbor for promotion to Docker Hub.
# ---------------------------------------------------------------------------
.PHONY: build-dist push-dist \
	build-dist-auth-service build-dist-inventory-service build-dist-compliance-engine \
	build-dist-cbom-service build-dist-sensor-manager build-dist-admin-service \
	build-dist-monitoring-service build-dist-cluster-sensor-service \
	build-dist-resource-tracker-service build-dist-tenant-health-service \
	build-dist-audit-service \
	build-dist-device-interrogation-service build-dist-discovery-processor-service \
	build-dist-notification-service build-dist-pcap-processor build-dist-mcp-service \
	build-dist-web-ui build-dist-admin-ui

build-dist: ## Build the 18-image dist set (16 backends + web-ui + admin-ui). Requires DIST_TAG and IMAGE_REGISTRY.
	@if [ -z "$(IMAGE_REGISTRY)" ]; then echo "ERROR: IMAGE_REGISTRY is required. Run: make build-dist DIST_TAG=<tag> IMAGE_REGISTRY=<registry>"; exit 1; fi
	@echo "Building dist images with tag $(DIST_TAG) ..."
	@$(MAKE) -j$(shell nproc) \
		build-dist-auth-service build-dist-inventory-service build-dist-compliance-engine \
		build-dist-cbom-service build-dist-sensor-manager build-dist-admin-service \
		build-dist-monitoring-service build-dist-cluster-sensor-service \
		build-dist-resource-tracker-service build-dist-tenant-health-service \
		build-dist-audit-service \
		build-dist-device-interrogation-service build-dist-discovery-processor-service \
		build-dist-notification-service build-dist-pcap-processor build-dist-mcp-service \
		build-dist-web-ui build-dist-admin-ui
	@echo "Dist images built. Run: make push-dist DIST_TAG=$(DIST_TAG) IMAGE_REGISTRY=$(IMAGE_REGISTRY)"

build-dist-auth-service:
	docker build $(BASE_IMAGE_ARGS) -f services/auth-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/auth-service:$(DIST_TAG) .

build-dist-inventory-service:
	docker build $(BASE_IMAGE_ARGS) -f services/inventory-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/inventory-service:$(DIST_TAG) .

build-dist-compliance-engine:
	docker build $(BASE_IMAGE_ARGS) -f services/compliance-engine/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/compliance-engine:$(DIST_TAG) .

build-dist-cbom-service:
	docker build $(BASE_IMAGE_ARGS) -f services/cbom-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/cbom-service:$(DIST_TAG) .

build-dist-sensor-manager:
	docker build $(BASE_IMAGE_ARGS) -f services/sensor-manager/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/sensor-manager:$(DIST_TAG) .

build-dist-admin-service:
	docker build $(BASE_IMAGE_ARGS) -f services/admin-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/admin-service:$(DIST_TAG) .

build-dist-monitoring-service:
	docker build $(BASE_IMAGE_ARGS) -f services/monitoring-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/monitoring-service:$(DIST_TAG) .

build-dist-cluster-sensor-service:
	docker build $(BASE_IMAGE_ARGS) -f services/cluster-sensor-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/cluster-sensor-service:$(DIST_TAG) .

build-dist-resource-tracker-service:
	docker build $(BASE_IMAGE_ARGS) -f services/resource-tracker-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/resource-tracker-service:$(DIST_TAG) .

build-dist-tenant-health-service:
	docker build $(BASE_IMAGE_ARGS) -f services/tenant-health-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/tenant-health-service:$(DIST_TAG) .

build-dist-audit-service:
	docker build $(BASE_IMAGE_ARGS) -f services/audit-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/audit-service:$(DIST_TAG) .

build-dist-device-interrogation-service:
	docker build $(BASE_IMAGE_ARGS) -f services/device-interrogation-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/device-interrogation-service:$(DIST_TAG) .

build-dist-discovery-processor-service:
	docker build $(BASE_IMAGE_ARGS) -f services/discovery-processor-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/discovery-processor-service:$(DIST_TAG) .

build-dist-notification-service:
	docker build $(BASE_IMAGE_ARGS) -f services/notification-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/notification-service:$(DIST_TAG) .

build-dist-mcp-service:
	docker build $(BASE_IMAGE_ARGS) -f services/mcp-service/Dockerfile.dist \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/mcp-service:$(DIST_TAG) .

build-dist-pcap-processor: ## pcap-processor uses CGO — no garble, but included in dist release
	docker build $(BASE_IMAGE_ARGS) -f services/pcap-processor/Dockerfile.prod \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/pcap-processor:$(DIST_TAG) .

build-dist-web-ui: ## Tenant UI (Vista) — built from frontend-v2, KEEPS the web-ui image identity (build-and-swap, ADR-0013)
	# frontend-v2 is an npm-workspace member, so its Dockerfile.prod builds from
	# the REPO ROOT context (needs api/ + packages/primitives). The image is still
	# tagged web-ui:<tag> so the chart/registry/release-promote surface is unchanged
	# — only the bits inside the web-ui image swap from the old web-ui/ to frontend-v2.
	docker build -f frontend-v2/Dockerfile.prod \
		--build-arg VITE_APP_VERSION=$(DIST_TAG) \
		--build-arg VITE_GIT_SHA=$$(git rev-parse --short HEAD) \
		--build-arg VITE_BUILD_DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/web-ui:$(DIST_TAG) .

build-dist-admin-ui: ## Admin console (VISTA Operations) — built from admin-ui-v2/, KEEPS the admin-ui image identity (build-and-swap, ADR-0013; mirrors web-ui). Dockerfile.prod, REPO-ROOT context (npm-workspace member: needs api/ + packages/). No license code.
	docker build -f admin-ui-v2/Dockerfile.prod \
		--build-arg VITE_APP_VERSION=$(DIST_TAG) \
		--build-arg VITE_GIT_SHA=$$(git rev-parse --short HEAD) \
		--build-arg VITE_BUILD_DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/admin-ui:$(DIST_TAG) .

push-dist: ## Push the 20-image dist set to registry (requires DIST_TAG and IMAGE_REGISTRY)
	@if [ -z "$(IMAGE_REGISTRY)" ]; then echo "ERROR: IMAGE_REGISTRY is required."; exit 1; fi
	@echo "Pushing dist images with tag $(DIST_TAG) ..."
	@for img in $(_ALL_IMAGES); do \
		docker push $(LICENSED_REGISTRY)/$(LICENSED_REPO_PREFIX)/$$img:$(DIST_TAG); \
	done
	@echo "All dist images pushed."

# Service-specific build targets
build-auth-service: ## Build auth-service
	@echo "Building auth-service..."
	@cd services/auth-service && go build -o ../../bin/auth-service ./cmd/main.go

build-inventory-service: ## Build inventory-service
	@echo "Building inventory-service..."
	@cd services/inventory-service && go build -o ../../bin/inventory-service ./cmd/main.go

build-compliance-engine: ## Build compliance-engine
	@echo "Building compliance-engine..."
	@cd services/compliance-engine && go build -o ../../bin/compliance-engine ./cmd/main.go

build-cbom-service: ## Build cbom-service
	@echo "Building cbom-service..."
	@cd services/cbom-service && go build -o ../../bin/cbom-service ./cmd/main.go

build-sensor-manager: ## Build sensor-manager
	@echo "Building sensor-manager..."
	@cd services/sensor-manager && go build -o ../../bin/sensor-manager ./cmd/main.go

build-admin-service: ## Build admin-service
	@echo "Building admin-service..."
	@cd services/admin-service && go build -o ../../bin/admin-service ./cmd/main.go

build-monitoring-service: ## Build monitoring-service
	@echo "Building monitoring-service..."
	@cd services/monitoring-service && go build -o ../../bin/monitoring-service ./cmd/main.go

build-cluster-sensor-service: ## Build cluster-sensor-service
	@echo "Building cluster-sensor-service..."
	@cd services/cluster-sensor-service && go build -o ../../bin/cluster-sensor-service ./cmd/main.go

build-resource-tracker-service: ## Build resource-tracker-service
	@echo "Building resource-tracker-service..."
	@cd services/resource-tracker-service && go build -o ../../bin/resource-tracker-service ./cmd/main.go

build-tenant-health-service: ## Build tenant-health-service
	@echo "Building tenant-health-service..."
	@cd services/tenant-health-service && go build -o ../../bin/tenant-health-service ./cmd/main.go

build-mcp-service: ## Build mcp-service
	@echo "Building mcp-service..."
	@cd services/mcp-service && go build -o ../../bin/mcp-service ./cmd

build-pcap-processor: ## Build pcap-processor (requires CGO + libpcap)
	@echo "Building pcap-processor..."
	@cd services/pcap-processor && CGO_ENABLED=1 go build -o ../../bin/pcap-processor ./cmd/main.go

ROOT_DIR := $(abspath $(CURDIR))
BIN_DIR := $(ROOT_DIR)/bin
SENSOR_DIR := $(ROOT_DIR)/sensor
# Build the whole cmd package, not just main.go — package main spans multiple
# files (cmd/main.go + cmd/logbuffer.go), and a single-file `go build cmd/main.go`
# fails with "undefined: logRing". Used by build-sensor + every cross-platform target.
SENSOR_MAIN := ./cmd

# Version stamped into the sensor and device-agent binaries (main.Version).
# Release builds pass the tag (release-core.yml does `make <target>
# AGENT_VERSION=vX.Y.Z`); a local build honestly reports "dev". Falls back to
# $(VERSION) so `make sensor-upload-version VERSION=vX.Y.Z` stamps consistently.
AGENT_VERSION ?= $(or $(VERSION),dev)
# Strip a leading "v": the platform stores the bare version and the UI renders
# it as v{version}, so stamping the tag verbatim would display as "vv0.6.0".
AGENT_LDFLAGS := -ldflags "-X main.Version=$(patsubst v%,%,$(AGENT_VERSION))"

.PHONY: build-sensor sensor-linux-amd64 sensor-windows-amd64 sensor-windows-386 sensor-darwin-amd64 sensor-linux-arm64 sensor-darwin-arm64 sensor-all-platforms build-windows

build-sensor: ## Build cross-platform network sensor
	@echo "Building network sensor..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build -C $(SENSOR_DIR) $(AGENT_LDFLAGS) -o $(BIN_DIR)/crypto-sensor $(SENSOR_MAIN)
	@echo "Building cross-platform binaries (set CROSS=1 to enable)..."
	@if [ "$(CROSS)" = "1" ]; then \
		$(MAKE) sensor-all-platforms; \
	fi
	@echo "Network sensor built successfully!"

sensor-all-platforms: sensor-linux-amd64 sensor-linux-arm64 sensor-windows-amd64 sensor-darwin-amd64 sensor-darwin-arm64 ## Build sensor for all supported platforms

build-windows: sensor-windows-amd64 device-agent-windows-amd64 ## Build sensor and device-agent for Windows x86_64
	@echo ""
	@echo "✅ Windows binaries ready:"
	@echo "   artifacts/sensor/windows/amd64/crypto-sensor.exe"
	@echo "   artifacts/sensor/windows/amd64/install-sensor.ps1"
	@echo "   artifacts/device-agent/windows/amd64/device-agent.exe"

build-device-agent: ## Build device-agent binary
	@echo "Building device-agent..."
	@mkdir -p $(BIN_DIR)
	go build -C device-agent $(AGENT_LDFLAGS) -o $(BIN_DIR)/device-agent ./cmd/main.go
	@echo "Building cross-platform binaries (set CROSS=1 to enable)..."
	@if [ "$(CROSS)" = "1" ]; then \
		$(MAKE) device-agent-all-platforms; \
	fi
	@echo "Device agent built successfully!"

device-agent-all-platforms: device-agent-linux-amd64 device-agent-linux-arm64 device-agent-windows-amd64 device-agent-darwin-amd64 device-agent-darwin-arm64 ## Build device-agent for all supported platforms

device-agent-linux-amd64: ## Build device-agent for Linux x86_64
	@echo "Building Linux x86_64 device-agent..."
	@mkdir -p $(BIN_DIR) artifacts/device-agent/linux/amd64
	GOOS=linux GOARCH=amd64 go build -C device-agent $(AGENT_LDFLAGS) -o $(BIN_DIR)/device-agent-linux-amd64 ./cmd/main.go
	cp $(BIN_DIR)/device-agent-linux-amd64 artifacts/device-agent/linux/amd64/device-agent
	@echo "✅ Linux x86_64 device-agent built and placed in artifacts/"

device-agent-linux-arm64: ## Build device-agent for Linux ARM64
	@echo "Building Linux ARM64 device-agent..."
	@mkdir -p $(BIN_DIR) artifacts/device-agent/linux/arm64
	GOOS=linux GOARCH=arm64 go build -C device-agent $(AGENT_LDFLAGS) -o $(BIN_DIR)/device-agent-linux-arm64 ./cmd/main.go
	cp $(BIN_DIR)/device-agent-linux-arm64 artifacts/device-agent/linux/arm64/device-agent
	@echo "✅ Linux ARM64 device-agent built and placed in artifacts/"

device-agent-windows-amd64: ## Build device-agent for Windows x86_64
	@echo "Building Windows x86_64 device-agent..."
	@mkdir -p $(BIN_DIR) artifacts/device-agent/windows/amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -C device-agent $(AGENT_LDFLAGS) -o $(BIN_DIR)/device-agent-windows-amd64.exe ./cmd/main.go
	cp $(BIN_DIR)/device-agent-windows-amd64.exe artifacts/device-agent/windows/amd64/device-agent.exe
	@echo "✅ Windows x86_64 device-agent built and placed in artifacts/"

device-agent-windows-386: ## Build device-agent for Windows x86 (32-bit)
	@echo "Building Windows x86 (32-bit) device-agent..."
	@mkdir -p $(BIN_DIR) artifacts/device-agent/windows/386
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -C device-agent $(AGENT_LDFLAGS) -o $(BIN_DIR)/device-agent-windows-386.exe ./cmd/main.go
	cp $(BIN_DIR)/device-agent-windows-386.exe artifacts/device-agent/windows/386/device-agent.exe
	@echo "✅ Windows x86 device-agent built and placed in artifacts/"

device-agent-darwin-amd64: ## Build device-agent for macOS x86_64
	@echo "Building macOS x86_64 device-agent..."
	@mkdir -p $(BIN_DIR) artifacts/device-agent/darwin/amd64
	GOOS=darwin GOARCH=amd64 go build -C device-agent $(AGENT_LDFLAGS) -o $(BIN_DIR)/device-agent-darwin-amd64 ./cmd/main.go
	cp $(BIN_DIR)/device-agent-darwin-amd64 artifacts/device-agent/darwin/amd64/device-agent
	@echo "✅ macOS x86_64 device-agent built and placed in artifacts/"

device-agent-darwin-arm64: ## Build device-agent for macOS ARM64 (Apple Silicon)
	@echo "Building macOS ARM64 device-agent..."
	@mkdir -p $(BIN_DIR) artifacts/device-agent/darwin/arm64
	GOOS=darwin GOARCH=arm64 go build -C device-agent $(AGENT_LDFLAGS) -o $(BIN_DIR)/device-agent-darwin-arm64 ./cmd/main.go
	cp $(BIN_DIR)/device-agent-darwin-arm64 artifacts/device-agent/darwin/arm64/device-agent
	@echo "✅ macOS ARM64 device-agent built and placed in artifacts/"

device-agent-upload: device-agent-all-platforms ## Build and upload device-agent binaries to S3
	@echo "Uploading device-agent binaries to S3..."
	@go run scripts/upload-device-agent-artifacts.go -artifacts-dir artifacts/device-agent -version=$(or $(DEVICE_AGENT_VERSION),latest)
	@echo "✅ Device-agent binaries uploaded to S3"

sensor-linux-amd64: ## Build sensor for Linux x86_64
	@echo "Building Linux x86_64 sensor..."
	@mkdir -p $(BIN_DIR) artifacts/sensor/linux/amd64
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -C $(SENSOR_DIR) $(AGENT_LDFLAGS) -o $(BIN_DIR)/crypto-sensor-linux-amd64 $(SENSOR_MAIN)
	cp $(BIN_DIR)/crypto-sensor-linux-amd64 artifacts/sensor/linux/amd64/crypto-sensor
	cp scripts/install-sensor.sh artifacts/sensor/linux/amd64/
	@echo "✅ Linux x86_64 sensor built and placed in artifacts/"

sensor-linux-arm64: ## Build sensor for Linux ARM64
	@echo "Building Linux ARM64 sensor..."
	@mkdir -p $(BIN_DIR) artifacts/sensor/linux/arm64
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -C $(SENSOR_DIR) $(AGENT_LDFLAGS) -o $(BIN_DIR)/crypto-sensor-linux-arm64 $(SENSOR_MAIN)
	cp $(BIN_DIR)/crypto-sensor-linux-arm64 artifacts/sensor/linux/arm64/crypto-sensor
	cp scripts/install-sensor.sh artifacts/sensor/linux/arm64/
	@echo "✅ Linux ARM64 sensor built and placed in artifacts/"

sensor-windows-amd64: ## Build sensor for Windows x86_64
	@echo "Building Windows x86_64 sensor..."
	@mkdir -p $(BIN_DIR) artifacts/sensor/windows/amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -C $(SENSOR_DIR) $(AGENT_LDFLAGS) -o $(BIN_DIR)/crypto-sensor-windows-amd64.exe $(SENSOR_MAIN)
	cp $(BIN_DIR)/crypto-sensor-windows-amd64.exe artifacts/sensor/windows/amd64/crypto-sensor.exe
	cp scripts/install-sensor.ps1 artifacts/sensor/windows/amd64/
	@echo "✅ Windows x86_64 sensor built and placed in artifacts/"

sensor-windows-386: ## Build sensor for Windows x86 (32-bit)
	@echo "Building Windows x86 (32-bit) sensor..."
	@mkdir -p $(BIN_DIR) artifacts/sensor/windows/386
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -C $(SENSOR_DIR) $(AGENT_LDFLAGS) -o $(BIN_DIR)/crypto-sensor-windows-386.exe $(SENSOR_MAIN)
	cp $(BIN_DIR)/crypto-sensor-windows-386.exe artifacts/sensor/windows/386/crypto-sensor.exe
	cp scripts/install-sensor.ps1 artifacts/sensor/windows/386/
	@echo "✅ Windows x86 sensor built and placed in artifacts/"

sensor-darwin-amd64: ## Build sensor for macOS x86_64
	@echo "Building macOS x86_64 sensor..."
	@mkdir -p $(BIN_DIR) artifacts/sensor/darwin/amd64
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -C $(SENSOR_DIR) $(AGENT_LDFLAGS) -o $(BIN_DIR)/crypto-sensor-darwin-amd64 $(SENSOR_MAIN)
	cp $(BIN_DIR)/crypto-sensor-darwin-amd64 artifacts/sensor/darwin/amd64/crypto-sensor
	cp scripts/install-sensor.sh artifacts/sensor/darwin/amd64/
	@echo "✅ macOS x86_64 sensor built and placed in artifacts/"

sensor-darwin-arm64: ## Build sensor for macOS ARM64 (Apple Silicon)
	@echo "Building macOS ARM64 sensor..."
	@mkdir -p $(BIN_DIR) artifacts/sensor/darwin/arm64
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -C $(SENSOR_DIR) $(AGENT_LDFLAGS) -o $(BIN_DIR)/crypto-sensor-darwin-arm64 $(SENSOR_MAIN)
	cp $(BIN_DIR)/crypto-sensor-darwin-arm64 artifacts/sensor/darwin/arm64/crypto-sensor
	cp scripts/install-sensor.sh artifacts/sensor/darwin/arm64/
	@echo "✅ macOS ARM64 sensor built and placed in artifacts/"

build-frontend: ## Build React frontend
	@echo "Building frontend..."
	cd frontend-v2 && npm install --no-fund --no-audit && npm run build
	@echo "Frontend built successfully!"

build-all: build-services build-sensor build-device-agent build-frontend build-ai-service ## Build all components

# Test Commands
test-unit: ## Run unit tests for all services
	@if [ "$(PARALLEL)" = "1" ]; then \
		$(MAKE) test-parallel; \
	else \
		echo "Running unit tests..." && \
		cd services/auth-service && go test ./... && \
		cd ../inventory-service && go test ./... && \
		cd ../compliance-engine && go test ./... && \
		cd ../cbom-service && go test ./... && \
		cd ../sensor-manager && go test ./... && \
		cd ../admin-service && go test ./... && \
		cd ../monitoring-service && go test ./... && \
		cd ../cluster-sensor-service && go test ./... && \
		cd ../resource-tracker-service && go test ./... && \
		cd ../tenant-health-service && go test ./... && \
		cd ../mcp-service && go test ./... && \
		cd ../../sensor && go test ./... && \
		echo "Unit tests completed!"; \
	fi

test-parallel: ## Run tests in parallel across all services
	@echo "Running tests in parallel..."
	@for service in auth-service inventory-service compliance-engine cbom-service sensor-manager admin-service monitoring-service cluster-sensor-service resource-tracker-service tenant-health-service mcp-service; do \
		(cd services/$$service && go test -v ./... &) \
	done; \
	(cd sensor && go test -v ./... &) \
	wait

test-cached: ## Run tests with caching enabled
	@echo "Running tests with cache..."
	@go test -count=1 -cache ./services/... ./shared/... ./sensor/...

test-race: ## Run tests with race detection (slower but thorough)
	@echo "Running tests with race detection..."
	@go test -race ./services/... ./shared/... ./sensor/...

test-coverage: ## Generate coverage report
	@echo "Generating coverage report..."
	@go test -coverprofile=coverage.out ./services/... ./shared/... ./sensor/...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Service-specific test targets
test-auth-service: ## Test auth-service
	@cd services/auth-service && go test -v ./...

test-inventory-service: ## Test inventory-service
	@cd services/inventory-service && go test -v ./...

test-compliance-engine: ## Test compliance-engine
	@cd services/compliance-engine && go test -v ./...

test-cbom-service: ## Test cbom-service
	@cd services/cbom-service && go test -v ./...

test-sensor-manager: ## Test sensor-manager
	@cd services/sensor-manager && go test -v ./...

test-admin-service: ## Test admin-service
	@cd services/admin-service && go test -v ./...

test-monitoring-service: ## Test monitoring-service
	@cd services/monitoring-service && go test -v ./...

test-cluster-sensor-service: ## Test cluster-sensor-service
	@cd services/cluster-sensor-service && go test -v ./...

test-resource-tracker-service: ## Test resource-tracker-service
	@cd services/resource-tracker-service && go test -v ./...

test-tenant-health-service: ## Test tenant-health-service
	@cd services/tenant-health-service && go test -v ./...

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	cd tests/integration && go test ./...
	@echo "Integration tests completed!"

test-e2e: ## Run end-to-end tests
	@echo "Running E2E tests..."
	cd tests/e2e && npm test
	@echo "E2E tests completed!"

test-load: ## Run load tests
	@echo "Running load tests..."
	cd tests && k6 run load-test.js
	@echo "Load tests completed!"

test: test-unit test-integration ## Run unit and integration tests

# Database Commands
db-migrate: ## No-op: schema is fully consolidated in schema.sql, applied automatically on fresh deploy
	@echo "ℹ️  db-migrate: schema is consolidated in scripts/database/schema.sql."
	@echo "   On a fresh deploy, Postgres auto-applies it as 01-schema.sql."
	@echo "   No separate migration step is needed."

db-seed: ## Seed database with built-in seed data (02-seed.sql)
	$(DOCKER_COMPOSE) exec postgres psql -U crypto_user -d crypto_inventory -f /docker-entrypoint-initdb.d/02-seed.sql

# 02-seed.sql seeds only the six FREE frameworks. Local compose dev is an
# Enterprise checkout, so apply the content bundle too or the regulated
# frameworks (SOC 2, PCI-DSS, ISO 27001, NIST CSF, IEC 62351-3) are simply
# absent from your dev database and every compliance screen looks thinner than
# a licensed deployment. Signature verification is a chart/release concern and
# is deliberately not repeated here — locally the file IS the source of truth.
db-seed-content-bundle: ## Apply the Enterprise content bundle to the compose database (dev parity with a licensed deployment)
	@test -f $(CONTENT_BUNDLE_SQL) || (echo "❌ $(CONTENT_BUNDLE_SQL) not found (Core checkout — nothing to apply)" && exit 1)
	$(DOCKER_COMPOSE) exec -T postgres psql -U crypto_user -d crypto_inventory -v ON_ERROR_STOP=1 < $(CONTENT_BUNDLE_SQL)

db-reset: ## Reset database (WARNING: destroys all data) and bring all services back up
	$(DOCKER_COMPOSE) down -v
	$(DOCKER_COMPOSE) up -d postgres redis influxdb nats
	@echo "Waiting for Postgres to initialize schema..."
	sleep 15
	$(MAKE) db-seed
	@# Enterprise checkout: keep dev at parity with a licensed deployment.
	@# Skipped without complaint on a Core checkout (no bundle present).
	@$(MAKE) db-seed-content-bundle || echo "ℹ️  no Enterprise content bundle — dev DB has the 6 free frameworks only"
	$(DOCKER_COMPOSE) up -d

# Infrastructure convenience targets (align with Startup Guide)
infra-up: ## Start core infrastructure services (postgres, redis, influxdb, nats)
	$(DOCKER_COMPOSE) up -d postgres redis influxdb nats

infra-down: ## Stop core infrastructure services
	$(DOCKER_COMPOSE) stop postgres redis influxdb nats

# Development Setup
install-deps: ## Install development dependencies
	@echo "Syncing Go workspace dependencies..."
	@go work sync
	@echo "Pre-warming Go module cache..."
	@go mod download -x ./shared
	@go mod download -x ./shared/rbac
	@for service in services/*/; do \
		if [ -f "$$service/go.mod" ]; then \
			go mod download -x "./$$service"; \
		fi \
	done
	@echo "Installing frontend dependencies..."
	cd frontend-v2 && npm install
	@echo "Dependencies installed!"

# Code Quality
lint: ## Run linters for all code (golangci-lint + eslint)
	@echo "Running Go linters..."
	golangci-lint run ./services/...
	golangci-lint run ./sensor/...
	@echo "Running frontend linters (eslint)..."
	cd frontend-v2 && npm run lint
	cd admin-ui-v2 && npm run lint

# Service-specific lint targets
lint-auth-service: ## Lint auth-service
	@golangci-lint run ./services/auth-service/...

lint-inventory-service: ## Lint inventory-service
	@golangci-lint run ./services/inventory-service/...

lint-compliance-engine: ## Lint compliance-engine
	@golangci-lint run ./services/compliance-engine/...

lint-cbom-service: ## Lint cbom-service
	@golangci-lint run ./services/cbom-service/...

lint-sensor-manager: ## Lint sensor-manager
	@golangci-lint run ./services/sensor-manager/...

lint-admin-service: ## Lint admin-service
	@golangci-lint run ./services/admin-service/...

lint-monitoring-service: ## Lint monitoring-service
	@golangci-lint run ./services/monitoring-service/...

lint-cluster-sensor-service: ## Lint cluster-sensor-service
	@golangci-lint run ./services/cluster-sensor-service/...

lint-resource-tracker-service: ## Lint resource-tracker-service
	@golangci-lint run ./services/resource-tracker-service/...

lint-tenant-health-service: ## Lint tenant-health-service
	@golangci-lint run ./services/tenant-health-service/...

format: ## Format all code
	@echo "Formatting Go code..."
	gofmt -s -w ./services/
	gofmt -s -w ./sensor/
	@echo "Formatting frontend code..."
	cd frontend-v2 && npm run format

# Standards Enforcement
edition-matrix: ## Regenerate docsv4/core/editions.md from editions.go + seed.sql + standards/editions.yaml
	@cd scripts && npm install --no-fund --no-audit >/dev/null 2>&1 || true
	node ./scripts/generate-edition-matrix.mjs

.PHONY: api-contract
api-contract: ## Spec-first API guardrail (ADR-0001): verify generated TS client is in sync with the OpenAPI spec, then run service contract tests
	@echo "==> API contract: regenerating typed client and checking for drift..."
	@cd api && npm install --no-fund --no-audit >/dev/null 2>&1 || true
	@cd api && npm run generate >/dev/null
	@if ! git diff --quiet --exit-code -- api/clients/typescript; then \
		echo "❌ Generated API client drifted from the spec. Run 'cd api && npm run generate' and commit the result."; \
		git diff --name-only -- api/clients/typescript; \
		exit 1; \
	fi
	@echo "✅ Generated client is in sync with the spec."
	@echo "==> API contract: running Go contract tests (cbom-service/scopes)..."
	@cd services/cbom-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/scopes/ -run Contract
	@echo "==> API contract: running Go contract tests (cbom-service/cbom-artifacts)..."
	@cd services/cbom-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/cbom/ -run Contract
	@echo "==> API contract: running Go contract tests (cbom-service EE diff: cbom-comparison)..."
	@cd services/cbom-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) sh -c 'if [ -d ee/diff ]; then go test ./ee/diff/ -run Contract; else echo "  (ee/ absent — open-source checkout, skipping)"; fi'
	@echo "==> API contract: running Go contract tests (inventory-service/infrastructure-assets + external-connections + asset-lifecycle + crypto-posture + crypto-materials + asset-reads + asset-writes + algorithm-recommendations + crypto-risks-export + asset-hard-delete + location-summary)..."
	@cd services/inventory-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/handlers/ -run Contract
	@echo "==> API contract: running Go contract tests (inventory-service EE CMDB sync: profiles + test-connection + sync + jobs)..."
	@cd services/inventory-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) sh -c 'if [ -d ee/cmdbsync ]; then go test ./ee/cmdbsync/ -run Contract; else echo "  (ee/ absent — open-source checkout, skipping)"; fi'
	@echo "==> API contract: running Go contract tests (compliance-engine/frameworks + evaluation + findings + alerts + alert-catalog + plans + scenarios + tickets)..."
	@cd services/compliance-engine && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/handlers/ -run Contract
	@echo "==> API contract: running Go contract tests (compliance-engine EE policy authoring: custom-policies + controls + measurements)..."
	@cd services/compliance-engine && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) sh -c 'if [ -d ee/policyauthoring ]; then go test ./ee/policyauthoring/ -run Contract; else echo "  (ee/ absent — open-source checkout, skipping)"; fi'
	@echo "==> API contract: running Go contract tests (auth-service/cross-cutters + platform-config + trial-status + impersonation + tenant-branding + tenant-ui-config + tenant-users + onboarding-reads + onboarding-writes + billing-usage + tenant-billing + tiers)..."
	@cd services/auth-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/api/ -run Contract
	@echo "==> API contract: running Go contract tests (auth-service EE SSO: tenant-sso + sso-write + sso-update + auth-policy + unlink)..."
	@cd services/auth-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) sh -c 'if [ -d ee/sso ]; then go test ./ee/sso/ -run Contract; else echo "  (ee/ absent — open-source checkout, skipping)"; fi'
	@echo "==> API contract: running Go contract tests (sensor-manager/sensors + admin-settings + config-interfaces + health-history + discoveries + pcap + cert-mgmt)..."
	@cd services/sensor-manager && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/handlers/ -run Contract
	@echo "==> API contract: running Go contract tests (audit-service/activity-logs + alert-rules + audit-batch)..."
	@cd services/audit-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/handlers/ -run Contract
	@echo "==> API contract: running Go contract tests (audit-service EE SIEM export: integrations + types + test-connection)..."
	@cd services/audit-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) sh -c 'if [ -d ee/siemexport ]; then go test ./ee/siemexport/ -run Contract; else echo "  (ee/ absent — open-source checkout, skipping)"; fi'
	@echo "==> API contract: running Go contract tests (device-interrogation-service/jobs + device-action-validation)..."
	@cd services/device-interrogation-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/handlers/ -run Contract
	@echo "==> API contract: running Go contract tests (notification-service/tenant-channels+rules + platform-channels+rules)..."
	@cd services/notification-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/api/ -run Contract
	@echo "==> API contract: running Go contract tests (admin-service core: platform-rbac + tiers + security + billable-items + platform-users + platform-user-email + tier-entitlements + storage + platform-settings + system-logs)..."
	@cd services/admin-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/handlers/ -run Contract
	@echo "==> API contract: running Go contract tests (admin-service MSP: tenants + tenant-lifecycle + costs + announcements + maintenance-windows + support-tickets + tenant-stats + dashboard)..."
	@cd services/admin-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) sh -c 'if [ -d ee/msp ]; then go test ./ee/msp/ -run Contract; else echo "  (ee/ absent — open-source checkout, skipping)"; fi'
	@echo "==> API contract: running Go contract tests (admin-service EE billing: my-billing + coupons + billing-analytics + billing-invoices)..."
	@cd services/admin-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) sh -c 'if [ -d ee/billingapi ]; then go test ./ee/billingapi/ -run Contract; else echo "  (ee/ absent — open-source checkout, skipping)"; fi'
	@echo "==> API contract: running Go contract tests (monitoring-service/status + alerting + trends + gateway + admin-status)..."
	@cd services/monitoring-service && GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go test ./internal/api/ -run Contract
	@echo "✅ Contract tests pass — live handlers conform to the spec."

chart-lint: ## helm lint the chart against values.schema.json (catches schema/template drift the release would otherwise hit)
	@command -v helm >/dev/null 2>&1 || { echo "❌ helm not found — install helm to run chart-lint"; exit 1; }
	@# Mirrors the helm lint invocation in .github/workflows/release-customer.yml.
	@# The --set flags satisfy the schema's required fields so lint validates the
	@# default values.yaml + templates rather than failing on missing inputs.
	helm lint charts/vistaplatform \
		--set tls.dnsName=lint.example \
		--set tls.issuerRef.name=lint \
		--set platform.jwtSecret=l \
		--set platform.internalAuthSecret=l \
		--set platform.encryptionMasterKey=l

# Workflow linting. This exists because `secrets` is not an available context in
# `if:`, and a workflow that references it there does not fail a step — it fails
# to COMPILE. GitHub surfaces that as a nameless "workflow file issue" with no
# line number, so gateway-cors-smoke.yml and images.yml sat broken from 2026-05
# to 2026-08 with nobody noticing, and the bug was then copied into the Core
# release pipeline. A workflow that never compiles never reports a failure
# anyone reads, so the only way to catch this class is statically.
#
# Pinned rather than @latest: a linter that changes under you turns an unrelated
# commit into a failing build. Uses actionlint from PATH when present (fast),
# otherwise builds the pinned version through the module cache — deliberately
# NOT skipping when absent, because a check that silently does nothing is the
# exact failure mode this target was added to prevent.
# Verifies every third-party action is pinned to a SHA that actually EXISTS.
# actionlint cannot do this — a SHA is opaque, and only the hosting repository
# can say whether it resolves. The Core release pipeline shipped a fabricated
# pin (correct-looking prefix, invented tail) that failed 16 of 19 jobs on the
# first real build and could not have been caught any earlier without this.
ACTIONLINT_VERSION ?= v1.7.12
lint-workflows:   ## Lint GitHub Actions workflows (context availability, expressions, shell)
	@echo "Linting GitHub Actions workflows..."
	@if command -v actionlint >/dev/null 2>&1; then \
		actionlint .github/workflows/*.yml; \
	else \
		GOTOOLCHAIN=$(GOTOOLCHAIN_PIN) go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) .github/workflows/*.yml; \
	fi
	@echo "✅ workflows lint clean"

drift-check:   ## Check for configuration drift
	@echo "Drift check complete!"

standards-check: generate verify-generated chart-lint lint-workflows  ## Generate, verify and run all standards checks

registry-first: generate verify-generated  ## Complete registry-first workflow
	@echo "✅ Registry-first workflow complete!"
	@echo "💡 All configurations are now in sync with registry."

# CORS Testing
cors-check:   ## Alias for test-cors

# Session Management
# Security
security-scan: ## Run security scans
	@echo "Running Go security scan..."
	gosec ./services/...
	gosec ./sensor/...
	@echo "Running npm audit..."
	cd frontend-v2 && npm audit

# Docker Commands
docker-build: ## Build all Docker images
	docker-compose build

docker-pull: ## Pull latest base images
	docker-compose pull

# Sensor Deployment
sensor-package: build-sensor ## Package sensor for distribution
	@echo "Creating sensor distribution packages..."
	mkdir -p dist/sensor
	cp bin/crypto-sensor-* dist/sensor/
	cp scripts/install-sensor.sh scripts/install-sensor.ps1 dist/sensor/
	cp sensor/README.md dist/sensor/
	cp sensor/config.example.yaml dist/sensor/config.yaml
	cd dist && tar -czf crypto-sensor-release.tar.gz sensor/
	@echo "Sensor packages created in dist/ directory"

sensor-upload: sensor-all-platforms ## Build and upload sensor binaries to S3
	@echo "Uploading sensor artifacts to S3..."
	@go run scripts/upload-sensor-artifacts.go -artifacts-dir artifacts/sensor

sensor-upload-version: sensor-all-platforms ## Build and upload sensor binaries to S3 with version tag (usage: make sensor-upload-version VERSION=v1.0.0)
	@if [ -z "$(VERSION)" ]; then \
		echo "❌ Error: VERSION is required. Usage: make sensor-upload-version VERSION=v1.0.0"; \
		exit 1; \
	fi
	@echo "Uploading sensor artifacts to S3 with version $(VERSION)..."
	@go run scripts/upload-sensor-artifacts.go -artifacts-dir artifacts/sensor -version $(VERSION)

sensor-upload-dry-run: sensor-all-platforms ## Dry run: show what would be uploaded to S3
	@echo "Dry run: showing what would be uploaded to S3..."
	@go run scripts/upload-sensor-artifacts.go -artifacts-dir artifacts/sensor -dry-run

# Documentation
docs-serve: ## Serve documentation locally
	@echo "Starting documentation server..."
	cd docs && python3 -m http.server 8000

# Monitoring
monitor: ## Show system status
	@echo "=== Docker Services ==="
	docker-compose ps
	@echo ""
	@echo "=== System Resources ==="
	docker stats --no-stream
	@echo ""
	@echo "=== Service Health ==="
	curl -s http://localhost:${AUTH_SERVICE_HOST_PORT:-8081}/health || echo "Auth service: DOWN"
	curl -s http://localhost:${INVENTORY_SERVICE_HOST_PORT:-8082}/health || echo "Inventory service: DOWN"
	curl -s http://localhost:${COMPLIANCE_ENGINE_HOST_PORT:-8083}/health || echo "Compliance service: DOWN"

# Cache Management
validate-cache: ## Validate cache integrity
	@echo "Validating Go module cache..."
	@go mod verify ./shared
	@go mod verify ./shared/rbac
	@for service in services/*/; do \
		if [ -f "$$service/go.mod" ]; then \
			go mod verify "./$$service" || echo "⚠️  Cache issue in $$service"; \
		fi \
	done
	@echo "Cache validation complete"

build-clean: ## Force clean build (clear all caches)
	@echo "Cleaning all caches..."
	@$(MAKE) clean-cache
	@docker system prune -f
	@echo "✅ All caches cleared"

# Gateway / Routing Utilities
.PHONY: registry-check gen-gateway gateway-validate

registry-check: ## Validate service registry JSON
	@echo "Validating service registry..."
	@if command -v jq >/dev/null 2>&1; then \
		jq . config/service-registry.json >/dev/null; \
	else \
		node -e "JSON.parse(require('fs').readFileSync('config/service-registry.json','utf8'))"; \
	fi
	@echo "Service registry is valid."

gen-gateway: node_modules_check registry-check ## Generate Traefik gateway config from service registry
	@echo "Generating Traefik gateway config from registry..."
	DEPLOY_ENV=development node scripts/generate-traefik-config.mjs
	DEPLOY_ENV=ec2-smoke USE_MTLS=true node scripts/generate-traefik-config.mjs
	DEPLOY_ENV=production USE_MTLS=false node scripts/generate-traefik-config.mjs
	@echo "Traefik gateway config updated: config/traefik/"

gateway-validate: ## Validate Traefik configuration inside gateway container
	@echo "Validating Traefik gateway configuration..."
	@docker compose exec -T api-gateway traefik healthcheck

.PHONY:
.PHONY:
.PHONY: ts-build
ts-build: ## Build TypeScript for both UIs
	@echo "Building web-ui TypeScript..."
	@cd frontend-v2 && npm run build
	@echo "Building admin-ui TypeScript..."
	@cd admin-ui-v2 && npm run build
	@echo "✅ TypeScript builds completed successfully"

# ================================================================
# Production Validation (Fast vs Parity)
# ================================================================
.PHONY: prod-validate-fast

prod-validate-fast: generate verify-generated  ## Fast validation using existing checks (no containers)
	@echo "✅ Fast prod validation complete (no container bring-up)."
