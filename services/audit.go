package services

// Audit service.
type Audit struct {
	client AuditClient
}

// AuditClient contains methods used by the Audit service.
type AuditClient interface {
	AddsEvent(message string, severity string)
}

// NewAudit returns a Audit service.
func NewAudit(cs AuditClient) *Audit {
	return &Audit{client: cs}
}

// AddsEvent will create a new event on audit object.
func (p *Audit) AddsEvent(message string, severity string) {
	p.client.AddsEvent(message, severity)
}
