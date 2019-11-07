package services

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

// LoggerClient contains minimum interface required by the logger service.
type LoggerClient interface {
	Info(message string, a ...interface{})
	Warning(message string, a ...interface{})
	Error(message string, a ...interface{})
	Debug(message string, a ...interface{})
	Close()
}

// Logger client.
type Logger struct {
	client LoggerClient
}

// NewLogger initializes and returns a Logger struct.
func NewLogger(l LoggerClient) *Logger {
	return &Logger{client: l}
}

// Info sends a message to the logger using info as the severity.
func (l *Logger) Info(message string, a ...interface{}) {
	l.client.Info(message, a...)
}

// Warning sends a message to the logger using warning as the severity.
func (l *Logger) Warning(message string, a ...interface{}) {
	l.client.Warning(message, a...)
}

// Error sends a message to the logger using error as the severity.
func (l *Logger) Error(message string, a ...interface{}) {
	l.client.Error(message, a...)
}

// Debug sends a message to the logger using debug as the severity.
func (l *Logger) Debug(message string, a ...interface{}) {
	l.client.Debug(message, a...)
}

// Close buffer and send messages to stackdriver.
func (l *Logger) Close() {
	l.client.Close()
}
