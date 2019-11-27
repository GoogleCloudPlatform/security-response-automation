package clients

import (
	"github.com/googlecloudplatform/security-response-automation/services"
)

// Notification client
type Notification struct {
	logger *services.Logger
}

// NewNotification returns and initializes a Notification client.
func NewNotification(logger *services.Logger) *Notification {
	return &Notification{
		logger,
	}
}


// NotifyLogger sends audit object to the configured logger channel
func (n *Notification) NotifyLogger(audit *services.Audit){
	n.logger.LogAudit(audit)
}
