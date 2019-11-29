package services

type Notification struct {
	stackdriver *StackDriver
	email  *Email
}

type mailContent struct {
	Greeting string
	Actions string
	Finding string
}

// Notify sends notification for the channels configured
func (n *Notification) Notify(audit *AuditLog) []error{
	var errors []error

	n.notifyStackDriver(audit)
	err := n.notifyEmail(audit)
	if err != nil{
		errors = append(errors, err)
	}

	return errors
}

func (n *Notification) notifyStackDriver(audit *AuditLog){
	n.stackdriver.Notify(audit)
}

func (n *Notification) notifyEmail(audit *AuditLog) error{
	return n.email.Notify(audit)
}

// NewNotification returns a Notification client initialized.
func NewNotification(stackdriver *StackDriver, email *Email) *Notification {
	return &Notification{stackdriver: stackdriver, email: email}
}