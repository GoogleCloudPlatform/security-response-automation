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

// RuleName returns the rule name of the finding.
func (f *Finding) RuleName() string {
	if f.containerscanner.GetFinding().GetSourceProperties().GetScannerName() != "CONTAINER_SCANNER" {
		return ""
	}
	return strings.ToLower(f.containerscanner.GetFinding().GetCategory())
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
		Name:      f.containerscanner.GetFinding().GetName(),
	}
}

// StringToBeHashed returns the string that will be used to generate the mark hash finding.
func (f *Finding) StringToBeHashed() string {
	return f.containerscanner.GetFinding().GetEventTime() + f.containerscanner.GetFinding().GetName()
}

// SraRemediated returns the sraRemediate mark of the finding.
func (f *Finding) SraRemediated() string {
	return f.containerscanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated()
}

// Deserialize deserializes the finding in object.
func (f *Finding) Deserialize(b []byte) error {
	if err := json.Unmarshal(b, &f.containerscanner); err != nil {
		return err
	}
	return nil
}
