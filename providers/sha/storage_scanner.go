package sha

import (
	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

// StorageScanner is an abstraction around SHA's IAM Scanner finding.
type StorageScanner struct {
	// Fields found in every ETD finding not specific to this finding.
	*CommonFinding
}

// NewStorageScanner reads a pubsub message and creates a new finding.
func NewStorageScanner(ps *pubsub.Message) (*StorageScanner, error) {
	f := StorageScanner{CommonFinding: &CommonFinding{}}

	if err := f.ReadFinding(ps); err != nil {
		return nil, errors.New(err.Error())
	}

	if v := f.validate(); !v {
		return nil, errors.Wrap(entities.ErrValueNotFound, "fields did not validate")
	}
	return &f, nil
}

// validate ensures the fields to be accessed by getter methods are valid.
func (f *StorageScanner) validate() bool {
	// TODO: Implement this.
	return true
}
