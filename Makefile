PROVIDER_PORT ?= 7100
DEMO_APP_A_PORT ?= 7101
DEMO_APP_B_PORT ?= 7102
PROTECT_PORT ?= 7200
UPSTREAM_PORT ?= 3000
UPSTREAM ?= http://127.0.0.1:$(UPSTREAM_PORT)
DATA_DIR ?= .anyauth
PIN ?= 123456
AGENT_ID ?= codex
AGENT_NAME ?= Codex Local Agent
TASK_NAME ?= Local demo task
DELEGATION_SCOPE ?= app.read
POLICY_ALLOW_ID ?= allow-hello
POLICY_DENY_ID ?= deny-admin
AUTHZ_APPLICATION_ID ?= github
AUTHZ_APPLICATION_NAME ?= GitHub
AUTHZ_ACTION ?= issue.create
AUTHZ_RESOURCE_TYPE ?= repository
AUTHZ_RESOURCE_ID ?= yukunlabs/anyauth
AUTHZ_TASK_ID ?= local-authz-demo
AUTHZ_TASK ?= Improve AnyAuth authorization

.PHONY: fmt fmt-check test build script-check smoke-protect smoke-agent-protect smoke-policy-protect smoke-authz verify ci run demo protect protect-agent dev-upstream user-show set-pin clear-pin agent-add agents-list delegate-token delegate-list policy-allow-hello policy-deny-admin policies-list application-add applications-list authz-request authz-check authz-requests authz-grants audit-list clean clean-state

fmt:
	gofmt -w cmd internal

fmt-check:
	@if [ -n "$$(gofmt -l cmd internal)" ]; then gofmt -l cmd internal; exit 1; fi

test:
	go test ./...

build:
	go build -o bin/anyauth ./cmd/anyauth

script-check:
	python3 -m py_compile scripts/dev_upstream.py

smoke-protect:
	go test ./internal/localdev -run TestProtectGatewayFlow -v

smoke-agent-protect:
	go test ./internal/localdev -run TestProtectGatewayWithDelegation -v

smoke-policy-protect:
	go test ./internal/localdev -run TestProtectGatewayEnforcesPolicy -v

smoke-authz:
	go test ./internal/localdev -run TestSemanticAuthorizationApprovalFlow -v

verify: fmt test build smoke-protect smoke-agent-protect smoke-policy-protect smoke-authz script-check

ci: fmt-check test build smoke-protect smoke-agent-protect smoke-policy-protect smoke-authz script-check

run:
	go run ./cmd/anyauth serve -provider-port $(PROVIDER_PORT) -data-dir $(DATA_DIR)

demo:
	go run ./cmd/anyauth demo -provider-port $(PROVIDER_PORT) -app-a-port $(DEMO_APP_A_PORT) -app-b-port $(DEMO_APP_B_PORT) -data-dir $(DATA_DIR)

protect:
	go run ./cmd/anyauth protect -provider-port $(PROVIDER_PORT) -port $(PROTECT_PORT) -upstream $(UPSTREAM) -data-dir $(DATA_DIR)

protect-agent:
	go run ./cmd/anyauth protect -provider-port $(PROVIDER_PORT) -port $(PROTECT_PORT) -upstream $(UPSTREAM) -data-dir $(DATA_DIR) --require-delegation

dev-upstream:
	python3 scripts/dev_upstream.py --port $(UPSTREAM_PORT)

user-show:
	go run ./cmd/anyauth user show -data-dir $(DATA_DIR)

set-pin:
	printf "%s\n" "$(PIN)" | go run ./cmd/anyauth user set-pin -data-dir $(DATA_DIR) --pin-stdin

clear-pin:
	go run ./cmd/anyauth user clear-pin -data-dir $(DATA_DIR)

agent-add:
	go run ./cmd/anyauth agents add -data-dir $(DATA_DIR) --id $(AGENT_ID) --name "$(AGENT_NAME)"

agents-list:
	go run ./cmd/anyauth agents list -data-dir $(DATA_DIR)

delegate-token:
	@printf "%s\n" "$(PIN)" | go run ./cmd/anyauth delegate create -data-dir $(DATA_DIR) --agent $(AGENT_ID) --provider-port $(PROVIDER_PORT) --protect-port $(PROTECT_PORT) --task "$(TASK_NAME)" --scope $(DELEGATION_SCOPE) --format token --pin-stdin

delegate-list:
	go run ./cmd/anyauth delegate list -data-dir $(DATA_DIR)

policy-allow-hello:
	go run ./cmd/anyauth policy add -data-dir $(DATA_DIR) --id $(POLICY_ALLOW_ID) --effect allow --method GET --path-prefix /hello --scope $(DELEGATION_SCOPE)

policy-deny-admin:
	go run ./cmd/anyauth policy add -data-dir $(DATA_DIR) --id $(POLICY_DENY_ID) --effect deny --path-prefix /admin

policies-list:
	go run ./cmd/anyauth policy list -data-dir $(DATA_DIR)

application-add:
	go run ./cmd/anyauth applications add -data-dir $(DATA_DIR) --id $(AUTHZ_APPLICATION_ID) --name "$(AUTHZ_APPLICATION_NAME)" --action $(AUTHZ_ACTION) --resource-type $(AUTHZ_RESOURCE_TYPE)

applications-list:
	go run ./cmd/anyauth applications list -data-dir $(DATA_DIR)

authz-request:
	go run ./cmd/anyauth authz request --provider-url http://127.0.0.1:$(PROVIDER_PORT) --agent $(AGENT_ID) --application $(AUTHZ_APPLICATION_ID) --action $(AUTHZ_ACTION) --resource-type $(AUTHZ_RESOURCE_TYPE) --resource $(AUTHZ_RESOURCE_ID) --task-id $(AUTHZ_TASK_ID) --task "$(AUTHZ_TASK)"

authz-check:
	go run ./cmd/anyauth authz check -data-dir $(DATA_DIR) --provider-url http://127.0.0.1:$(PROVIDER_PORT) --agent $(AGENT_ID) --application $(AUTHZ_APPLICATION_ID) --action $(AUTHZ_ACTION) --resource-type $(AUTHZ_RESOURCE_TYPE) --resource $(AUTHZ_RESOURCE_ID) --task-id $(AUTHZ_TASK_ID)

authz-requests:
	go run ./cmd/anyauth authz requests -data-dir $(DATA_DIR)

authz-grants:
	go run ./cmd/anyauth authz grants -data-dir $(DATA_DIR)

audit-list:
	go run ./cmd/anyauth audit list -data-dir $(DATA_DIR)

clean:
	rm -rf bin __pycache__ scripts/__pycache__
	find . -name '*.pyc' -delete

clean-state:
	rm -rf .anyauth
