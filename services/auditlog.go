package services

import (
	"time"
)

// Journal structure.
type Journal struct {
	finding string
	events []Entry
}

// Entry structure
type Entry struct {
	date string
	text string
	isError bool
}

// NewAuditLog returns a Journal client initialized.
func NewAuditLog(finding string) *Journal {
	return &Journal{finding: finding}
}

// Add will create a new successful entry on audit object.
func (p *Journal) Add(text string) {
	p.events = append(p.events, Entry{
		date: time.Now().String(),
		text: text,
		isError: false,
	})
}

// AddError will create a new error entry on audit object.
func (p *Journal) AddError(text string) {
	p.events = append(p.events, Entry{
		date:    time.Now().String(),
		text:    text,
		isError: true,
	})
}