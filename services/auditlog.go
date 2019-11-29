package services

import (
	"time"
)

// AuditLog structure.
type AuditLog struct {
	finding string
	events []Entry
}

// Entry structure
type Entry struct {
	date string
	text string
	isError bool
}

// NewAuditLog returns a AuditLog client initialized.
func NewAuditLog(finding string) *AuditLog {
	return &AuditLog{finding: finding}
}

// Add will create a new successful entry on audit object.
func (p *AuditLog) Add(text string) {
	p.events = append(p.events, Entry{
		date: time.Now().String(),
		text: text,
		isError: false,
	})
}

// AddError will create a new error entry on audit object.
func (p *AuditLog) AddError(text string) {
	p.events = append(p.events, Entry{
		date:    time.Now().String(),
		text:    text,
		isError: true,
	})
}