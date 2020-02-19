package datasetscanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/bigquery/closepublicdataset"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Finding represents this finding structure by SHA scanner.
type Finding struct {
	datasetScanner *pb.DatasetScanner
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
	if err := json.Unmarshal(b, &f.datasetScanner); err != nil {
		return nil, err
	}
	if f.AlreadyRemediated() {
		return nil, fmt.Errorf("remediation ignored! Finding already processed and remediated. Security Mark: \"sra-remediated-event-time: %s\"", f.sraRemediated())
	}
	return &f, nil
}

// ClosePublicDataset returns values for the close public dataset automation.
func (f *Finding) ClosePublicDataset() *closepublicdataset.Values {
	return &closepublicdataset.Values{
		ProjectID: f.datasetScanner.GetFinding().GetSourceProperties().GetProjectID(),
		DatasetID: sha.Dataset(f.datasetScanner.GetFinding().GetResourceName()),
		Mark:      f.datasetScanner.GetFinding().GetEventTime(),
		Name:      f.datasetScanner.GetFinding().GetName(),
	}
}

// sraRemediated returns the mark sra-remediated-event-time.
func (f *Finding) sraRemediated() string {
	marks := f.datasetScanner.GetFinding().GetSecurityMarks().GetMarks()
	if marks != nil {
		return marks["sra-remediated-event-time"]
	}
	return ""
}

// AlreadyRemediated returns if the finding was remediated before or not.
func (f *Finding) AlreadyRemediated() bool {
	return f.sraRemediated() == f.datasetScanner.GetFinding().GetEventTime()
}
