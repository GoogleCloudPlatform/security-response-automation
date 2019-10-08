package sha

import (
	"encoding/json"

	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

const (
	iamScannerName        = "IAM_SCANNER"
	errorMsgNotIamScanner = "not a IAM_SCANNER Finding"
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
	// Fields found in every SHA finding not specific to this finding.
	*Finding
	// Fields specific to this finding.
	fields iamScanner
}

// NewIamScanner reads a pubsub message and creates a new finding.
func NewIamScanner(ps *pubsub.Message) (*IamScanner, error) {
	f := IamScanner{Finding: NewFinding()}

	if err := f.ReadFinding(ps); err != nil {
		return nil, errors.New(err.Error())
	}

	if err := json.Unmarshal(ps.Data, &f.fields); err != nil {
		return nil, entities.ErrUnmarshal
	}

	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *IamScanner) validate() error {

	if f.ScannerName() != iamScannerName {
		return errors.New(errorMsgNotIamScanner)
	}

	return nil
}
