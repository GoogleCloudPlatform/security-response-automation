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
// AddsInfoEvent will create a new event on audit object with severity INFO.
func (p *Audit) AddsInfoEvent(message string) {
	p.client.AddsEvent(message, "INFO")
}

// AddsDebugEvent will create a new event on audit object with severity DEBUG.
func (p *Audit) AddsDebugEvent(message string) {
	p.client.AddsEvent(message, "DEBUG")
}

// AddsErrorEvent will create a new event on audit object with severity ERROR.
func (p *Audit) AddsErrorEvent(message string) {
	p.client.AddsEvent(message, "ERROR")
}

// AddsWarningEvent will create a new event on audit object with severity WARNING.
func (p *Audit) AddsWarningEvent(message string) {
	p.client.AddsEvent(message, "WARNING")
}