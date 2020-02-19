package iamscanner

import (
	"encoding/json"
	"fmt"
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
	if f.AlreadyRemediated() {
		return nil, fmt.Errorf("remediation ignored! Finding already processed and remediated. Security Mark: \"sra-remediated-event-time: %s\"", f.sraRemediated())
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
		Mark:      f.iamScanner.GetFinding().GetEventTime(),
		Name:      f.iamScanner.GetFinding().GetName(),
	}
}

// sraRemediated returns the mark sra-remediated-event-time.
func (f *Finding) sraRemediated() string {
	marks := f.iamScanner.GetFinding().GetSecurityMarks().GetMarks()
	if marks != nil {
		return marks["sra-remediated-event-time"]
	}
	return ""
}

// AlreadyRemediated returns if the finding was remediated before or not.
func (f *Finding) AlreadyRemediated() bool {
	return f.sraRemediated() == f.iamScanner.GetFinding().GetEventTime()
}
