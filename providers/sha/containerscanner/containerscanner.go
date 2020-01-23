package containerscanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gke/disabledashboard"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Finding represents this finding.
type Finding struct {
	containerscanner *pb.ContainerScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.ContainerScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	if finding.GetFinding().GetSourceProperties().GetScannerName() != "CONTAINER_SCANNER" {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.containerscanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// DisableDashboard returns values for the disable dashboard automation.
func (f *Finding) DisableDashboard() *disabledashboard.Values {
	return &disabledashboard.Values{
		ProjectID: f.containerscanner.GetFinding().GetSourceProperties().GetProjectID(),
		Zone:      sha.ClusterZone(f.containerscanner.GetFinding().GetResourceName()),
		ClusterID: sha.ClusterID(f.containerscanner.GetFinding().GetResourceName()),
		Hash:      f.containerscanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated(),
	}
}

// EventTime returns the eventTime of the finding.
func (f *Finding) EventTime() string {
	return f.containerscanner.GetFinding().GetEventTime()
}
