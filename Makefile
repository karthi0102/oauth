.PHONY: run build tidy seed run-all

run-auth:
	go run ./cmd/auth-server

run-resource:
	go run ./cmd/resource-server

run-client:
	go run ./cmd/client-app

run-all:
	make -j3 run-auth run-resource run-client

build:
	go build -o bin/auth-server     ./cmd/auth-server
	go build -o bin/resource-server ./cmd/resource-server
	go build -o bin/client-app      ./cmd/client-app

tidy:
	go mod tidy

test:
	go test ./...