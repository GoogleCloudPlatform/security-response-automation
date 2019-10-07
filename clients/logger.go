package clients

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/logging"
	"google.golang.org/api/option"
)

const loggerName = "security-response-automation"

var projectID = os.Getenv("GCP_PROJECT")

// Logger client.
type Logger struct {
	client *logging.Client
	logger *logging.Logger
}

// NewLogger initializes and returns a Logger struct.
func NewLogger(ctx context.Context, authFile string) (*Logger, error) {
	c, err := logging.NewClient(ctx, projectID, option.WithCredentialsFile(authFile))
	if err != nil {
		return nil, fmt.Errorf("failed to init logger: %q", err)
	}
	return &Logger{client: c, logger: c.Logger(loggerName)}, nil
}

// Info sends a message to the logger using info as the severity.
func (l *Logger) Info(message string, a ...interface{}) {
	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Info})
}

// Warning sends a message to the logger using warning as the severity.
func (l *Logger) Warning(message string, a ...interface{}) {
	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Warning})
}

//Error sends a message to the logger using error as the severity.
func (l *Logger) Error(message string, a ...interface{}) {
	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Error})
}

// Debug sends a message to the logger using debug as the severity.
func (l *Logger) Debug(message string, a ...interface{}) {
	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Debug})
}

// Close buffer and send messages to stackdriver
func (l *Logger) Close() {
	l.client.Close()
}
