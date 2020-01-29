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
	datasetScanner *pb.DatasetScanner
}

// RuleName returns the category of the finding.
func (f *Finding) RuleName() string {
	if f.datasetScanner.GetFinding().GetSourceProperties().GetScannerName() != "DATASET_SCANNER" {
		return ""
	}
	return strings.ToLower(f.datasetScanner.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.datasetScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// ClosePublicDataset returns values for the close public dataset automation.
func (f *Finding) ClosePublicDataset() *closepublicdataset.Values {
	return &closepublicdataset.Values{
		ProjectID: f.datasetScanner.GetFinding().GetSourceProperties().GetProjectID(),
		DatasetID: sha.Dataset(f.datasetScanner.GetFinding().GetResourceName()),
		Hash:      f.datasetScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated(),
		Name:      f.datasetScanner.GetFinding().GetName(),
	}
}

// StringToBeHashed returns the string that will be used to generate the mark hash finding.
func (f *Finding) StringToBeHashed() string {
	return f.datasetScanner.GetFinding().GetEventTime() + f.datasetScanner.GetFinding().GetName()
}

// SraRemediated returns the sraRemediate mark of the finding.
func (f *Finding) SraRemediated() string {
	return f.datasetScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated()
}

// Deserialize deserializes the finding in object.
func (f *Finding) Deserialize(b []byte) error {
	if err := json.Unmarshal(b, &f.datasetScanner); err != nil {
		return err
	}
	return nil
}
