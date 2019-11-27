package clients
// Audit client.
type Audit struct {
	finding string
	messages []string
}

// NewAudit returns a Audit client initialized.
func NewAudit(finding string) *Audit {
	return &Audit{finding:finding}
}

// AddsEvent will create a new event on audit object.
func (p *Audit) AddsEvent(message string) {
	p.messages = append(p.messages, message)
}
