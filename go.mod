module github.com/cypherlabdev/user-service

go 1.22.0

toolchain go1.24.2

require (
	github.com/go-playground/validator/v10 v10.19.0
	github.com/golang-migrate/migrate/v4 v4.17.0

	// Utilities
	github.com/google/uuid v1.6.0
	// github.com/cypherlabdev/cypherlabdev-protos v0.1.0 // Temporarily disabled for testing

	// Database
	github.com/jackc/pgx/v5 v5.7.0
	github.com/pashagolub/pgxmock/v4 v4.3.0

	// Observability
	github.com/prometheus/client_golang v1.19.0

	// Redis
	github.com/redis/go-redis/v9 v9.5.1

	// Logging
	github.com/rs/zerolog v1.32.0

	// Kafka
	github.com/segmentio/kafka-go v0.4.47

	// Configuration
	github.com/spf13/viper v1.18.2

	// Testing
	github.com/stretchr/testify v1.9.0
	github.com/testcontainers/testcontainers-go v0.29.1
	github.com/testcontainers/testcontainers-go/modules/postgres v0.29.1
	github.com/testcontainers/testcontainers-go/modules/redis v0.29.1
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0
	go.opentelemetry.io/otel v1.24.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.24.0
	go.uber.org/mock v0.4.0

	// Authentication
	golang.org/x/crypto v0.27.0
	// gRPC & Protobuf
	google.golang.org/grpc v1.62.0
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
