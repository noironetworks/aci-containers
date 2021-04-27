.PHONY: all local test test-local integration-test-local install-deps lint fmt

all: test

local: install-deps fmt lint build-local test-local bench-local

build-local: 
	@echo "+ $@"
	@go build -v .

test-local:
	@echo "+ $@"
	@go test -race -coverprofile=unit.cov -short -v ./...

bench-local:
	@echo "+ $@"
	@go test -run=XXX -count=3 -bench=. | tee bench.out
	@benchstat bench.out

integration-test-local:
	@echo "+ $@"
	@go test -race -v -coverprofile=integration.cov -run Integration ./...

test:
	@docker-compose pull
	@docker-compose run --rm test

install-deps:
	@echo "+ $@"
	@golangci-lint --version
	@go install golang.org/x/perf/cmd/benchstat@latest

lint:
	@echo "+ $@"
	@golangci-lint run

fmt:
	@echo "+ $@"
	@test -z "$$(gofmt -s -l . | tee /dev/stderr)"