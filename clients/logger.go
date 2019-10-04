package clients

import (
	"context"
	"fmt"

	"cloud.google.com/go/logging"
	"google.golang.org/api/option"
)

// Logger exported
type Logger struct {
	client *logging.Client
	logger *logging.Logger
}

// NewLogger initializes and return a Logger struct
func NewLogger(ctx context.Context, authFile string) (*Logger, error) {
	projectName, loggerName := "pedro-audit", "my-default-logger"

	logging.EntryCountThreshold(0)
	c, err := logging.NewClient(ctx, projectName, option.WithCredentialsFile(authFile))
	if err != nil {
		return nil, fmt.Errorf("failed to init logger: %q", err)
	}

	if err := c.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to pings logger: %q", err)
	}

	l := c.Logger(loggerName)

	return &Logger{client: c, logger: l}, nil
}

//Info push info log to buffer
func (l *Logger) Info(message string, a ...interface{}) {

	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Info})
}

//Warning push warning log to buffer
func (l *Logger) Warning(message string, a ...interface{}) {

	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Warning})
}

//Error push error log to buffer
func (l *Logger) Error(message string, a ...interface{}) {

	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Error})
}

//Debug push debug log to buffer
func (l *Logger) Debug(message string, a ...interface{}) {

	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Debug})
}

//Close buffer and send messages to stackdriver
func (l *Logger) Close() {
	l.client.Close()
}
