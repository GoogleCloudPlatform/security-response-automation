package sha

import (
	"encoding/json"

	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

type iamScanner struct {
	Finding struct {
		Name             string
		SourceProperties struct {
			OffendingIamRoles string
		}
	}
}

// IamScanner is an abstraction around SHA's IAM Scanner finding.
type IamScanner struct {
	// Fields found in every ETD finding not specific to this finding.
	base *CommonFinding
	// Fields specific to this finding.
	fields iamScanner
}

// NewIamScanner reads a pubsub message and creates a new finding.
func NewIamScanner(ps *pubsub.Message) (*IamScanner, error) {
	var f IamScanner
	if err := json.Unmarshal(ps.Data, &f.fields); err != nil {
		return nil, entities.ErrUnmarshal
	}

	b := NewCommonFinding()

	if err := b.ReadFinding(ps); err != nil {
		return nil, errors.New(err.Error())
	}

	f.base = b
	if v := f.validate(); !v {
		return nil, errors.Wrap(entities.ErrValueNotFound, "fields did not validate")
	}
	return &f, nil
}

// validate ensures the fields to be accessed by getter methods are valid.
func (f *IamScanner) validate() bool {
	// TODO: Implement this.
	return true
}

// ScannerName returns the finding's scanner name.
func (f *IamScanner) ScannerName() string {
	return f.base.ScannerName()
}

// ProjectID returns the finding's project ID.
func (f *IamScanner) ProjectID() string {
	return f.base.ProjectID()
}
