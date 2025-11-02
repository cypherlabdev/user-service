package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Application metrics for user service
var (
	// Login metrics
	LoginAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "user_login_attempts_total",
			Help: "Total number of login attempts",
		},
		[]string{"status"}, // success, failure
	)

	// Session metrics
	ActiveSessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "user_active_sessions",
			Help: "Current number of active sessions",
		},
	)

	SessionValidationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "user_session_validations_total",
			Help: "Total number of session validations",
		},
		[]string{"status"}, // valid, invalid, expired
	)

	// Database metrics
	DatabaseQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "database_query_duration_seconds",
			Help:    "Duration of database queries in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"operation"}, // create, read, update, delete
	)

	DatabaseErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "database_errors_total",
			Help: "Total number of database errors",
		},
		[]string{"operation"},
	)

	// Redis metrics
	RedisOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "redis_operation_duration_seconds",
			Help:    "Duration of Redis operations in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5},
		},
		[]string{"operation"}, // get, set, delete
	)

	RedisErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_errors_total",
			Help: "Total number of Redis errors",
		},
		[]string{"operation"},
	)

	// User metrics
	UsersCreatedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "users_created_total",
			Help: "Total number of users created",
		},
	)

	UsersDeletedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "users_deleted_total",
			Help: "Total number of users deleted",
		},
	)

	PasswordChangesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "password_changes_total",
			Help: "Total number of password changes",
		},
	)

	// Kafka metrics
	KafkaPublishTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kafka_publish_total",
			Help: "Total number of Kafka messages published",
		},
		[]string{"topic", "status"}, // success, failure
	)

	KafkaPublishDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kafka_publish_duration_seconds",
			Help:    "Duration of Kafka publish operations in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5},
		},
		[]string{"topic"},
	)
)
