# NexusPanel developer entrypoints (P0)
SHELL := /bin/bash
PATH := $(PATH):/home/z/tools/go/bin

.PHONY: help dev build test typecheck agent agent-test cp-install cp-dev web-install web-dev db-up db-down

help:
	@echo "NexusPanel monorepo targets:"
	@echo "  db-up / db-down   - start/stop dev PostgreSQL 16 + Valkey (docker compose)"
	@echo "  cp-install        - install control-plane dependencies"
	@echo "  cp-dev            - run control-plane in dev mode (port 3000)"
	@echo "  agent / agent-test- build / test the Go agent"
	@echo "  web-install       - install web dependencies"
	@echo "  web-dev           - run web app in dev mode (port 5173)"
	@echo "  build / test      - workspace-wide build / test"

db-up:
	docker compose -f docker-compose.dev.yml up -d
db-down:
	docker compose -f docker-compose.dev.yml down

cp-install:
	npm install --workspace apps/control-plane
cp-dev:
	npm run dev --workspace apps/control-plane

agent:
	cd apps/agent && go build -o bin/nexuspanel-agent ./cmd/agent
agent-test:
	cd apps/agent && go vet ./... && go test ./...

web-install:
	npm install --workspace apps/web
web-dev:
	npm run dev --workspace apps/web

build:
	npm run build --workspaces --if-present
	cd apps/agent && go build -o bin/nexuspanel-agent ./cmd/agent

test:
	npm run test --workspaces --if-present
	cd apps/agent && go test ./...

typecheck:
	npm run typecheck --workspaces --if-present
