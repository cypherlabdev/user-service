# User Service

Authentication and session management microservice for the TAM sports betting platform.

## Overview

**user-service** handles user authentication, session management, and is the foundational service that all other microservices depend on for auth validation.

### Key Features

- **Session-based Authentication**: Redis-backed sessions with 24h TTL
- **Secure Password Storage**: bcrypt with cost factor 12
- **Event-Driven**: Publishes login/logout events to Kafka
- **Production-Ready**: Metrics, tracing, structured logging, health checks
- **Comprehensive Testing**: Unit tests (>80% coverage) + integration tests with testcontainers

## Technology Stack

- **Language**: Go 1.21+
- **Database**: PostgreSQL (users, refresh tokens)
- **Cache**: Redis (session storage)
- **Messaging**: Kafka (event publishing)
- **gRPC**: Inter-service communication
- **Observability**: Prometheus, OpenTelemetry, Zerolog

## Architecture

### Session Management

Sessions are stored in Redis (NOT JWT tokens):
- **Session ID**: UUID stored in Redis with 24h TTL
- **Key Pattern**: `session:{session_id}` → Session JSON
- **User Sessions**: `user_sessions:{user_id}` → Set of active session IDs
- **Auto-Refresh**: TTL extended on activity

### gRPC API

Implements 5 RPC methods from `tam-protos/user/v1`:

1. **Login** - Authenticate user and create session
2. **ValidateSession** - Check if session is valid
3. **GetSession** - Retrieve session information
4. **RefreshSession** - Extend session TTL
5. **CreateSession** - Create new session (internal)

## Quick Start

### Prerequisites

- Go 1.21+
- PostgreSQL 14+
- Redis 7+
- Kafka 3+ (optional for development)
- [golang-migrate](https://github.com/golang-migrate/migrate) for migrations

### Local Development Setup

1. **Install dependencies**:
```bash
make deps
```

2. **Start infrastructure** (PostgreSQL + Redis):
```bash
docker-compose up -d
```

3. **Run database migrations**:
```bash
make migrate-up
```

4. **Run the service**:
```bash
make run
```

5. **Verify health**:
```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

## Configuration

Configuration uses Viper with environment variable override support.

### Environment Variables

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=user_service
DB_USER=postgres
DB_PASSWORD=postgres

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Kafka
KAFKA_BROKER=localhost:9092

# Observability
JAEGER_ENDPOINT=localhost:14250
LOG_LEVEL=info
```

### Config Files

- `config/config.yaml` - Base configuration
- `config/config-dev.yaml` - Development overrides
- `config/config-production.yaml` - Production settings

## Database Schema

### users table
```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    created_at      TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP NOT NULL,
    deleted_at      TIMESTAMP,
    version         BIGINT NOT NULL
);
```

### refresh_tokens table
```sql
CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id),
    token_hash      VARCHAR(255) UNIQUE NOT NULL,
    expires_at      TIMESTAMP NOT NULL,
    created_at      TIMESTAMP NOT NULL,
    revoked_at      TIMESTAMP,
    ip_address      VARCHAR(45),
    user_agent      TEXT
);
```

See [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) for complete schema documentation.

## Development

### Run Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests only
make test-integration
```

### Generate Mocks

```bash
make mock
```

### Code Formatting

```bash
make fmt
make lint
```

## Deployment

### Kubernetes

Deploy using Helm:

```bash
helm install user-service ./charts/user-service -f values/production.yaml
```

### Health Checks

- **Liveness**: `GET /health` - Always returns 200 if service is running
- **Readiness**: `GET /ready` - Returns 200 only if PostgreSQL and Redis are healthy

### Metrics

Prometheus metrics exposed on `:9091/metrics`:

- `user_login_attempts_total{status}` - Login attempts (success/failure)
- `user_active_sessions` - Current active sessions
- `user_session_validations_total{status}` - Session validations
- `grpc_requests_total{method,status}` - gRPC request counts
- `grpc_request_duration_seconds{method}` - gRPC request latency
- `database_query_duration_seconds{operation}` - Database query latency
- `redis_operation_duration_seconds{operation}` - Redis operation latency

## API Documentation

See [docs/API.md](docs/API.md) for complete API documentation.

## Security

### Password Security

- **Hashing**: bcrypt with cost factor 12
- **Storage**: Only password hashes stored, never plain text
- **Validation**: Password verified during login using constant-time comparison

### Session Security

- **Storage**: Redis with TTL
- **Invalidation**: All sessions invalidated on password change
- **Activity Tracking**: Last activity timestamp updated on validation
- **Multi-Device**: Users can have multiple concurrent sessions

### Rate Limiting

**TODO**: Implement rate limiting (see [TAM-008](tickets.md))
- 5 login attempts per email per 15 minutes
- 20 login attempts per IP per 15 minutes

## Monitoring

### Logs

Structured JSON logs with Zerolog:

```json
{
  "level": "info",
  "user_id": "uuid-123",
  "session_id": "uuid-456",
  "ip": "192.168.1.1",
  "message": "user logged in successfully"
}
```

### Tracing

OpenTelemetry distributed tracing with Jaeger integration. All gRPC calls are traced with user context.

## Troubleshooting

### Common Issues

**Database connection failed**:
- Check PostgreSQL is running: `pg_isready -h localhost -p 5432`
- Verify credentials in config file
- Check migrations are up to date: `make migrate-up`

**Redis connection failed**:
- Check Redis is running: `redis-cli ping`
- Verify Redis host/port in config

**Session not found**:
- Sessions expire after 24 hours
- Check Redis for session: `redis-cli get session:{session_id}`

## Contributing

1. Follow patterns in [CLAUDE.md](CLAUDE.md)
2. Write tests for all new code (>80% coverage required)
3. Update documentation
4. Run `make lint` and `make fmt` before committing

## Project Structure

```
user-service/
├── cmd/server/              # Main application entry point
├── config/                  # Configuration files
├── internal/                # Private application code
│   ├── config/             # Configuration loading
│   ├── models/             # Domain models
│   ├── repository/         # Data access layer
│   ├── service/            # Business logic
│   ├── handler/            # gRPC handlers
│   ├── util/               # Utilities (crypto, validation)
│   ├── messaging/          # Kafka producers
│   └── observability/      # Metrics, tracing, logging
├── migrations/             # Database migrations
├── tests/integration/      # Integration tests
├── mocks/                  # Generated mocks
└── docs/                   # Documentation
```

## License

Proprietary - TAM Platform

## Support

For issues or questions:
- Check [CLAUDE.md](CLAUDE.md) for development guidelines
- Check [docs/](docs/) for detailed documentation
- Create ticket in [tickets.md](tickets.md)
- Contact platform team
