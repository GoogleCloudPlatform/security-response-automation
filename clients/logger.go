package clients

// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"context"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/logging"
)

const loggerName = "security-response-automation"

// projectID is the project ID where logs will be written to.
var projectID = os.Getenv("GCP_PROJECT")

// Logger client.
type Logger struct {
	client *logging.Client
	logger *logging.Logger
}

// NewLogger initializes and returns a Logger struct.
func NewLogger(ctx context.Context) (*Logger, error) {
	c, err := logging.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to init logger: %q", err)
	}
	return &Logger{client: c, logger: c.Logger(loggerName)}, nil
}

// Info sends a message to the logger using info as the severity.
func (l *Logger) Info(message string, a ...interface{}) {
	log.Printf(message, a...)
	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Info})
}

// Warning sends a message to the logger using warning as the severity.
func (l *Logger) Warning(message string, a ...interface{}) {
	log.Printf(message, a...)
	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Warning})
}

// Error sends a message to the logger using error as the severity.
func (l *Logger) Error(message string, a ...interface{}) {
	log.Printf(message, a...)
	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Error})
}

// Debug sends a message to the logger using debug as the severity.
func (l *Logger) Debug(message string, a ...interface{}) {
	log.Printf(message, a...)
	l.logger.Log(logging.Entry{Payload: fmt.Sprintf(message, a...), Severity: logging.Debug})
}

// Close buffer and send messages to stackdriver
func (l *Logger) Close() {
	l.client.Close()
}
