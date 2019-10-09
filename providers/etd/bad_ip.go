package etd

import (
	"encoding/json"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/pkg/errors"
)

type badIP struct {
	InsertID    string `json:"insertId"`
	LogName     string `json:"logName"`
	JSONPayload struct {
		AffectedResources []struct {
			GCPResourceName string
		}
		DetectionCategory struct {
			RuleName string
		}
		Properties struct {
			Location       string
			SourceInstance string
		}
	}
}

// BadIP is an ETD anomalous IAM grant subrule from StackDriver.
type BadIP struct {
	// Fields found in every ETD finding not specific to this finding.
	*Finding
	// Fields specific to this finding.
	fields badIP
}

// NewBadIP reads a pubsub message and creates a new finding.
func NewBadIP(ps *pubsub.Message) (*BadIP, error) {
	var f BadIP
	if err := json.Unmarshal(ps.Data, &f.fields); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	b, _ := NewFinding(ps)
	f.Finding = b
	if v := f.validate(); !v {
		return nil, errors.Wrap(entities.ErrValueNotFound, "fields did not validate")
	}
	return &f, nil
}

// validate ensures the fields to be accessed by getter methods are valid.
func (f *BadIP) validate() bool {
	// TODO: Implement this.
	return true
}

// Zone returns the zone of affected project.
func (f *BadIP) Zone() string {
	return f.fields.JSONPayload.Properties.Location
}

// Instance returns the zone of affected project.
func (f *BadIP) Instance() string {
	s := f.fields.JSONPayload.Properties.SourceInstance
	i := extractInstance.FindStringSubmatch(s)
	if len(i) != 2 {
		return ""
	}
	return i[1]
}
