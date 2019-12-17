package publicdataset

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/bigquery/closepublicdataset"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Automation defines the configuration for this finding.
type Automation struct {
	Action     string
	Target     []string
	Exclude    []string
	Properties struct {
		DryRun bool `yaml:"dry_run"`
	}
}

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
	return finding.GetFinding().GetCategory()
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
	}
}
