package clients

// Audit client.
type Audit struct {
	finding string
	events []Event
}

type Event struct {
	text string
	severity string
}

// NewAudit returns a Audit client initialized.
func NewAudit(finding string) *Audit {
	return &Audit{finding:finding}
}

// AddsEvent will create a new event on audit object.
func (p *Audit) AddsEvent(text string, severity string) {
	p.events = append(p.events, Event{
		text: text,
		severity: severity,
	})
}