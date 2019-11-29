package services

// Logger client.
type StackDriver struct {
	logger *Logger
	config *Configuration
}

// Notify writes all audited events to stackdriver
func (l *StackDriver) Notify(audit *AuditLog){
	if l.config.StackDriver.Enabled{
		for _, event := range audit.events{
			if !event.isError{
				l.logger.Info(event.text)
			} else {
				l.logger.Error(event.text)
			}
		}
	}

}

func NewStackDriver(logger *Logger, config *Configuration) *StackDriver{
	return &StackDriver{logger:logger, config: config}
}