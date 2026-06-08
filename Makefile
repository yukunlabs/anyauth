.PHONY: fmt test build run demo

fmt:
	gofmt -w cmd internal

test:
	go test ./...

build:
	go build -o bin/anyauth ./cmd/anyauth

run:
	go run ./cmd/anyauth serve

demo:
	go run ./cmd/anyauth demo
