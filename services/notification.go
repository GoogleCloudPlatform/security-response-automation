package services

import (
	"fmt"
)

type Notification struct {
	stackdriver *StackDriver
	email  *Email
	config *Configuration
}

func (n *Notification) Notify(audit *Journal){
	if n.config.StackDriver.Enabled{
		n.notifyStackDriver(audit)
	}
	if n.config.Email.Enabled{
		n.notifyEmail(audit)
	}
}

func (n *Notification) notifyStackDriver(audit *Journal){
	n.stackdriver.LogAudit(audit)
}

func (n *Notification) notifyEmail(audit *Journal){
	subject := "A security remediation was automatically done"
	var actions, status string
	for _, entry := range audit.events {
		status = "Remediation done successfully"
		if entry.isError{
			status = "Error trying to execute"
		}
		actions += fmt.Sprintf("%s - %s: %s \n", entry.date, status, entry.text)
	}
	body := fmt.Sprintf("Finding: %s \n Actions made: %s", audit.finding, actions)
	n.email.service.Send(subject, n.config.Email.From, body, n.config.Email.To)
}

// NewNotification returns a Notification client initialized.
func NewNotification(stackdriver *StackDriver, email *Email, config *Configuration) *Notification {
	return &Notification{stackdriver: stackdriver, email: email, config: config}
}