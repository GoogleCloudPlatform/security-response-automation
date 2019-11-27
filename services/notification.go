package services


type Notification struct {
	audit *Journal
	stackdriver *StackDriver
	pagerDuty   *PagerDuty
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
