package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

// Topics for user service events
const (
	TopicUserEvents    = "user-service.user.events"
	TopicSessionEvents = "user-service.session.events"
)

// EventProducer defines the interface for publishing events
type EventProducer interface {
	// PublishUserLogin publishes a user login event
	PublishUserLogin(ctx context.Context, event *UserLoginEvent) error

	// PublishUserLogout publishes a user logout event
	PublishUserLogout(ctx context.Context, event *UserLogoutEvent) error

	// PublishUserLogoutAll publishes a user logout all event
	PublishUserLogoutAll(ctx context.Context, event *UserLogoutAllEvent) error

	// PublishUserCreated publishes a user created event
	PublishUserCreated(ctx context.Context, event *UserCreatedEvent) error

	// PublishUserUpdated publishes a user updated event
	PublishUserUpdated(ctx context.Context, event *UserUpdatedEvent) error

	// PublishUserDeleted publishes a user deleted event
	PublishUserDeleted(ctx context.Context, event *UserDeletedEvent) error

	// PublishPasswordChanged publishes a password changed event
	PublishPasswordChanged(ctx context.Context, event *PasswordChangedEvent) error

	// PublishSessionCreated publishes a session created event
	PublishSessionCreated(ctx context.Context, event *SessionCreatedEvent) error

	// Close closes the producer
	Close() error
}

// kafkaEventProducer implements EventProducer using Kafka
type kafkaEventProducer struct {
	writer *kafka.Writer
	logger zerolog.Logger
}

// NewKafkaEventProducer creates a new Kafka event producer
func NewKafkaEventProducer(brokers []string, logger zerolog.Logger) EventProducer {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Balancer:     &kafka.Hash{}, // Hash by key for ordering
		MaxAttempts:  3,
		BatchSize:    100,
		BatchTimeout: 10 * time.Millisecond,
		Async:        true, // Async writes for performance
		Compression:  kafka.Snappy,
		Logger:       kafka.LoggerFunc(logger.Printf),
		ErrorLogger:  kafka.LoggerFunc(logger.Error().Msgf),
	}

	return &kafkaEventProducer{
		writer: writer,
		logger: logger.With().Str("component", "kafka_event_producer").Logger(),
	}
}

// publishEvent is a helper to publish any event
func (p *kafkaEventProducer) publishEvent(ctx context.Context, topic string, key string, event interface{}) error {
	// Serialize event to JSON
	data, err := json.Marshal(event)
	if err != nil {
		p.logger.Error().Err(err).Msg("failed to marshal event")
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Create Kafka message
	msg := kafka.Message{
		Topic: topic,
		Key:   []byte(key),
		Value: data,
		Time:  time.Now(),
	}

	// Write message
	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		p.logger.Error().
			Err(err).
			Str("topic", topic).
			Str("key", key).
			Msg("failed to publish event")
		return fmt.Errorf("failed to publish event: %w", err)
	}

	p.logger.Debug().
		Str("topic", topic).
		Str("key", key).
		Msg("event published successfully")

	return nil
}

// PublishUserLogin publishes a user login event
func (p *kafkaEventProducer) PublishUserLogin(ctx context.Context, event *UserLoginEvent) error {
	return p.publishEvent(ctx, TopicUserEvents, event.UserID, event)
}

// PublishUserLogout publishes a user logout event
func (p *kafkaEventProducer) PublishUserLogout(ctx context.Context, event *UserLogoutEvent) error {
	return p.publishEvent(ctx, TopicSessionEvents, event.SessionID, event)
}

// PublishUserLogoutAll publishes a user logout all event
func (p *kafkaEventProducer) PublishUserLogoutAll(ctx context.Context, event *UserLogoutAllEvent) error {
	return p.publishEvent(ctx, TopicUserEvents, event.UserID, event)
}

// PublishUserCreated publishes a user created event
func (p *kafkaEventProducer) PublishUserCreated(ctx context.Context, event *UserCreatedEvent) error {
	return p.publishEvent(ctx, TopicUserEvents, event.UserID, event)
}

// PublishUserUpdated publishes a user updated event
func (p *kafkaEventProducer) PublishUserUpdated(ctx context.Context, event *UserUpdatedEvent) error {
	return p.publishEvent(ctx, TopicUserEvents, event.UserID, event)
}

// PublishUserDeleted publishes a user deleted event
func (p *kafkaEventProducer) PublishUserDeleted(ctx context.Context, event *UserDeletedEvent) error {
	return p.publishEvent(ctx, TopicUserEvents, event.UserID, event)
}

// PublishPasswordChanged publishes a password changed event
func (p *kafkaEventProducer) PublishPasswordChanged(ctx context.Context, event *PasswordChangedEvent) error {
	return p.publishEvent(ctx, TopicUserEvents, event.UserID, event)
}

// PublishSessionCreated publishes a session created event
func (p *kafkaEventProducer) PublishSessionCreated(ctx context.Context, event *SessionCreatedEvent) error {
	return p.publishEvent(ctx, TopicSessionEvents, event.SessionID, event)
}

// Close closes the producer
func (p *kafkaEventProducer) Close() error {
	if err := p.writer.Close(); err != nil {
		p.logger.Error().Err(err).Msg("failed to close Kafka writer")
		return fmt.Errorf("failed to close Kafka writer: %w", err)
	}
	p.logger.Info().Msg("Kafka producer closed")
	return nil
}
