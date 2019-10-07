// Package sha holds methods and structures for SHA findings.
package sha

import (
	"encoding/json"

	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
)

type baseFinding struct {
	NotificationConfigName string
	Finding                struct {
		Name         string
		Parent       string
		ResourceName string
		State        string
		Category     string
		ExternalURI  string
	}
	SecurityMarks struct {
		Name string
	}
	EventTime  string
	CreateTime string
}

// Finding contains fields for a SHA finding.
type Finding struct {
	base *baseFinding
}

// NewFinding deserializes a basic ETD finding from StackDriver.
func NewFinding(m *pubsub.Message) (*Finding, error) {
	f := &Finding{}
	var bf baseFinding
	if err := json.Unmarshal(m.Data, &bf); err != nil {
		return f, entities.ErrUnmarshal
	}
	f.base = &bf
	return f, nil
}

// validate ensures the fields to be accessed by getter methods are valid.
func (f *Finding) validate() bool {
	// TODO: Implement this.
	return true
}

// Resource returns the affected resource name.
func (f *Finding) Resource() string {
	return f.base.Finding.ResourceName
}

// Category returns the category of the finding.
func (f *Finding) Category() string {
	return f.base.Finding.Category
}
