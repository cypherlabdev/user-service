package observability

import (
	"io"
	"os"

	"github.com/rs/zerolog"
)

// NewLogger creates a new structured logger with zerolog
func NewLogger(logLevel string) zerolog.Logger {
	// Parse log level
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}

	// Set global log level
	zerolog.SetGlobalLevel(level)

	// Configure time format
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Create multi-writer for stdout
	var writers []io.Writer
	writers = append(writers, zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "2006-01-02 15:04:05"})

	multi := zerolog.MultiLevelWriter(writers...)

	// Create logger
	logger := zerolog.New(multi).
		With().
		Timestamp().
		Caller().
		Logger()

	return logger
}
