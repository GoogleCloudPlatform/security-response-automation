package sha

import (
	"strings"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

const (
	storageScannerName        = "STORAGE_SCANNER"
	errorMsgNotStorageScanner = "not a STORAGE_SCANNER Finding"
	// resourcePrefix is the prefix before the bucket name in a SHA storage scanner finding.
	resourcePrefix = "//storage.googleapis.com/"
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

// BucketName returns name of the bucket. Resource assumed valid due to prior validate call.
func (f *StorageScanner) BucketName() string {
	return strings.Split(f.ResourceName(), resourcePrefix)[1]
}
