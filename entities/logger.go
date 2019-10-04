package entities

// LoggerClient contains minimum interface required by the logger entity.
type LoggerClient interface {
	Info(message string, a ...interface{})
	Warning(message string, a ...interface{})
	Error(message string, a ...interface{})
	Debug(message string, a ...interface{})
	Close()
}

//Logger exposed
type Logger struct {
	l LoggerClient
}

// NewLogger initializes and return a Logger struct
func NewLogger(l LoggerClient) *Logger {
	return &Logger{l: l}
}

//Info push info log to buffer
func (l *Logger) Info(message string, a ...interface{}) {
	l.l.Info(message, a)
}

//Warning push warning log to buffer
func (l *Logger) Warning(message string, a ...interface{}) {
	l.l.Warning(message, a)
}

//Error push error log to buffer
func (l *Logger) Error(message string, a ...interface{}) {
	l.l.Error(message, a)
}

//Debug push debug log to buffer
func (l *Logger) Debug(message string, a ...interface{}) {
	l.l.Debug(message, a)
}

//Close buffer and send messages to stackdriver
func (l *Logger) Close() {
	l.l.Close()
}
