PROVIDER_PORT ?= 7100
DEMO_APP_A_PORT ?= 7101
DEMO_APP_B_PORT ?= 7102
PROTECT_PORT ?= 7200
UPSTREAM_PORT ?= 3000
UPSTREAM ?= http://127.0.0.1:$(UPSTREAM_PORT)
DATA_DIR ?= .anyauth
PIN ?= 123456

.PHONY: fmt test build run demo protect dev-upstream smoke-protect user-show set-pin clear-pin

fmt:
	gofmt -w cmd internal

test:
	go test ./...

build:
	go build -o bin/anyauth ./cmd/anyauth

run:
	go run ./cmd/anyauth serve -provider-port $(PROVIDER_PORT) -data-dir $(DATA_DIR)

demo:
	go run ./cmd/anyauth demo -provider-port $(PROVIDER_PORT) -app-a-port $(DEMO_APP_A_PORT) -app-b-port $(DEMO_APP_B_PORT) -data-dir $(DATA_DIR)

protect:
	go run ./cmd/anyauth protect -provider-port $(PROVIDER_PORT) -port $(PROTECT_PORT) -upstream $(UPSTREAM) -data-dir $(DATA_DIR)

dev-upstream:
	python3 scripts/dev_upstream.py --port $(UPSTREAM_PORT)

smoke-protect:
	go test ./internal/localdev -run TestProtectGatewayFlow -v

user-show:
	go run ./cmd/anyauth user show -data-dir $(DATA_DIR)

set-pin:
	printf "%s\n" "$(PIN)" | go run ./cmd/anyauth user set-pin -data-dir $(DATA_DIR) --pin-stdin

clear-pin:
	go run ./cmd/anyauth user clear-pin -data-dir $(DATA_DIR)
