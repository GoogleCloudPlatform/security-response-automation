package sha

import (
	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

const (
	storageScannerName        = "STORAGE_SCANNER"
	errorMsgNotStorageScanner = "not a STORAGE_SCANNER Finding"
)

// StorageScanner is an abstraction around SHA's IAM Scanner finding.
type StorageScanner struct {
	// Fields found in every SHA finding not specific to this finding.
	*Finding
}

// NewStorageScanner reads a pubsub message and creates a new finding.
func NewStorageScanner(ps *pubsub.Message) (*StorageScanner, error) {
	f := StorageScanner{Finding: NewFinding()}

	if err := f.ReadFinding(ps); err != nil {
		return nil, errors.New(err.Error())
	}

	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *StorageScanner) validate() error {

	if f.ScannerName() != storageScannerName {
		return errors.New(errorMsgNotStorageScanner)
	}

	return nil
}
