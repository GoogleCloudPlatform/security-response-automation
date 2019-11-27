package services

import (
	"time"
)

// Audit structure.
type Audit struct {
	finding string
	events []Event
}

// Event structure
type Event struct {
	date string
	text string
	severity string
}

// NewAudit returns a Audit client initialized.
func NewAudit(finding string) *Audit {
	return &Audit{finding:finding}
}

// addsEvent will create a new event on audit object.
func (p *Audit) addsEvent(text string, severity string) {
	p.events = append(p.events, Event{
		date: time.Now().String(),
		text: text,
		severity: severity,
	})
}

// AddsInfoEvent will create a new event on audit object with severity INFO.
func (p *Audit) AddsInfoEvent(message string) {
	p.addsEvent(message, "INFO")
}

// AddsDebugEvent will create a new event on audit object with severity DEBUG.
func (p *Audit) AddsDebugEvent(message string) {
	p.addsEvent(message, "DEBUG")
}

// AddsErrorEvent will create a new event on audit object with severity ERROR.
func (p *Audit) AddsErrorEvent(message string) {
	p.addsEvent(message, "ERROR")
}

// AddsWarningEvent will create a new event on audit object with severity WARNING.
func (p *Audit) AddsWarningEvent(message string) {
	p.addsEvent(message, "WARNING")
}