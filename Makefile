.PHONY: help build run test test-unit test-integration clean migrate-up migrate-down mock proto lint fmt

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the service binary
	go build -o bin/user-service cmd/server/main.go

run: ## Run the service locally
	go run cmd/server/main.go

test: test-unit test-integration ## Run all tests

test-unit: ## Run unit tests
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./internal/...

test-integration: ## Run integration tests
	go test -v -race -tags=integration ./tests/integration/...

clean: ## Remove build artifacts
	rm -rf bin/
	rm -f coverage.txt

migrate-up: ## Run database migrations up
	migrate -path migrations -database "postgresql://localhost:5432/user_service?sslmode=disable" up

migrate-down: ## Run database migrations down
	migrate -path migrations -database "postgresql://localhost:5432/user_service?sslmode=disable" down

migrate-create: ## Create a new migration (usage: make migrate-create name=create_users_table)
	migrate create -ext sql -dir migrations -seq $(name)

mock: ## Generate mocks
	mockery --all

proto: ## Generate proto code from tam-protos
	@echo "Proto generation handled by tam-protos repository"
	@echo "Import github.com/tam/tam-protos/gen/go/user/v1 in your code"

lint: ## Run linters
	golangci-lint run

fmt: ## Format code
	go fmt ./...
	goimports -w .

deps: ## Download dependencies
	go mod download
	go mod tidy

docker-build: ## Build Docker image
	docker build -t user-service:latest .

docker-run: ## Run Docker container
	docker run -p 8080:8080 -p 9090:9090 user-service:latest
