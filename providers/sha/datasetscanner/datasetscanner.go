package datasetscanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/bigquery/closepublicdataset"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Finding represents this finding structure by SHA scanner.
type Finding struct {
	DatasetScanner *pb.DatasetScanner
}

// Name returns the category of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.DatasetScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	if finding.GetFinding().GetSourceProperties().GetScannerName() != "DATASET_SCANNER" {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.DatasetScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// ClosePublicDataset returns values for the close public dataset automation.
func (f *Finding) ClosePublicDataset() *closepublicdataset.Values {
	return &closepublicdataset.Values{
		ProjectID: f.DatasetScanner.GetFinding().GetSourceProperties().GetProjectID(),
		DatasetID: sha.Dataset(f.DatasetScanner.GetFinding().GetResourceName()),
	}
}
