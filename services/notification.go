package services


type Notification struct {
	stackdriver *StackDriver
	config *Configuration
}

func (n *Notification) Notify(audit *Journal){
	if n.config.StackDriver.Enabled{
		n.notifyStackDriver(audit)
	}
}

func (n *Notification) notifyStackDriver(audit *Journal){
	n.stackdriver.LogAudit(audit)
}

// NewNotification returns a Notification client initialized.
func NewNotification(stackdriver *StackDriver, config *Configuration) *Notification {
	return &Notification{stackdriver: stackdriver, config: config}
}