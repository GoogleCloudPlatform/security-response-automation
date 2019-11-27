package services


type Notification struct {
	audit *Journal
	stackdriver *StackDriver
}

func Notify(){

}

func (n *Notification) notifyLogger(audit *Journal){
	n.stackdriver.LogAudit(audit)
}