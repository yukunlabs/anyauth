.PHONY: fmt test build run

fmt:
	gofmt -w cmd internal

test:
	go test ./...

build:
	go build -o bin/anyauth ./cmd/anyauth

run:
	go run ./cmd/anyauth serve
