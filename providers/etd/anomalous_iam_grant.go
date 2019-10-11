package etd

import (
	"encoding/json"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/pkg/errors"
)

type externalMembersFinding struct {
	InsertID    string `json:"insertId"`
	LogName     string `json:"logName"`
	JSONPayload struct {
		AffectedResources []struct {
			GCPResourceName string
		}
		DetectionCategory struct {
			SubRuleName string
			RuleName    string
		}
		Properties struct {
			ProjectID       string `json:"project_id"`
			ExternalMembers []string
		}
	}
}

// ExternalMembersFinding is an abstraction around ETD's anomalous IAM grant finding.
type ExternalMembersFinding struct {
	// Fields found in every ETD finding not specific to this finding.
	*Finding
	// Fields specific to this finding.
	fields externalMembersFinding
}

// NewExternalMembersFinding reads a pubsub message and creates a new finding.
func NewExternalMembersFinding(ps *pubsub.Message) (*ExternalMembersFinding, error) {
	var f ExternalMembersFinding
	if err := json.Unmarshal(ps.Data, &f.fields); err != nil {
		return nil, entities.ErrUnmarshal
	}
	b, err := NewFinding(ps)
	if err != nil {
		return nil, err
	}
	f.Finding = b
	if v := f.validate(); !v {
		return nil, errors.Wrap(entities.ErrValueNotFound, "fields did not validate")
	}
	return &f, nil
}

// validate ensures the fields to be accessed by getter methods are valid.
func (f *ExternalMembersFinding) validate() bool {
	// TODO: Implement this.
	return true
}

// ExternalMembers returns the external members added.
func (f *ExternalMembersFinding) ExternalMembers() []string {
	return f.fields.JSONPayload.Properties.ExternalMembers
}

// ProjectID returns the project ID of affected project.
func (f *ExternalMembersFinding) ProjectID() string {
	return f.fields.JSONPayload.Properties.ProjectID
}
