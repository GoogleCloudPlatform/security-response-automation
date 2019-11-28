package services

// Logger client.
type StackDriver struct {
	logger *Logger
}

// LogAudit writes all audited events to stackdriver
func (l *StackDriver) LogAudit(audit *Journal){
	for _, event := range audit.events{
		if !event.isError{
			l.logger.Info(event.text)
		} else {
			l.logger.Error(event.text)
		}
	}
	l.logger.Close()
}

func NewStackDriver(logger *Logger) *StackDriver{
	return &StackDriver{logger:logger}
}