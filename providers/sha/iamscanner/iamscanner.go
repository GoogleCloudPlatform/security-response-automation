package iamscanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/removenonorgmembers"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
)

// Finding represents this finding structure by SHA scanner.
type Finding struct {
	iamScanner *pb.IamScanner
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.iamScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// Name returns the category of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.IamScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	if finding.GetFinding().GetSourceProperties().GetScannerName() != "IAM_SCANNER" {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// RemoveNonOrgMembers returns values for the remove non org members automation.
func (f *Finding) RemoveNonOrgMembers() *removenonorgmembers.Values {
	return &removenonorgmembers.Values{
		ProjectID: f.iamScanner.GetFinding().GetSourceProperties().GetProjectID(),
	}
}
