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
	*CommonFinding
	// Fields specific to this finding.
	fields iamScanner
}

// NewIamScanner reads a pubsub message and creates a new finding.
func NewIamScanner(ps *pubsub.Message) (*IamScanner, error) {
	f := IamScanner{CommonFinding: &CommonFinding{}}

	if err := f.ReadFinding(ps); err != nil {
		return nil, errors.New(err.Error())
	}

	if err := json.Unmarshal(ps.Data, &f.fields); err != nil {
		return nil, entities.ErrUnmarshal
	}

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
