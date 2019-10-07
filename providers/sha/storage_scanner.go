package sha

import (
	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

// StorageScanner is an abstraction around SHA's IAM Scanner finding.
type StorageScanner struct {
	// Fields found in every ETD finding not specific to this finding.
	base *CommonFinding
}

// NewStorageScanner reads a pubsub message and creates a new finding.
func NewStorageScanner(ps *pubsub.Message) (*StorageScanner, error) {
	var f StorageScanner
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
func (f *StorageScanner) validate() bool {
	// TODO: Implement this.
	return true
}

// ScannerName returns the finding's scanner name.
func (f *StorageScanner) ScannerName() string {
	return f.base.ScannerName()
}

// ProjectID returns the finding's project ID.
func (f *StorageScanner) ProjectID() string {
	return f.base.ProjectID()
}

// Category returns the finding Category
func (f *StorageScanner) Category() string {
	return f.base.Category()
}

// ResourceName returns the finding ResourceName
func (f *StorageScanner) ResourceName() string {
	return f.base.ResourceName()
}
