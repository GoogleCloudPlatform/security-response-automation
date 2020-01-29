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

// Category returns the category of the finding.
func (f *Finding) Category() string {
	if f.iamScanner.GetFinding().GetSourceProperties().GetScannerName() != "IAM_SCANNER" {
		return ""
	}
	return strings.ToLower(f.iamScanner.GetFinding().GetCategory())
}

// RemoveNonOrgMembers returns values for the remove non org members automation.
func (f *Finding) RemoveNonOrgMembers() *removenonorgmembers.Values {
	return &removenonorgmembers.Values{
		ProjectID: f.iamScanner.GetFinding().GetSourceProperties().GetProjectID(),
		Hash:      f.iamScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated(),
		Name:      f.iamScanner.GetFinding().GetName(),
	}
}

// StringToBeHashed returns the string that will be used to generate the mark hash finding.
func (f *Finding) StringToBeHashed() string {
	return f.iamScanner.GetFinding().GetEventTime() + f.iamScanner.GetFinding().GetName()
}

// SraRemediated returns the sraRemediate mark of the finding.
func (f *Finding) SraRemediated() string {
	return f.iamScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated()
}

// Deserialize deserializes the finding in object.
func (f *Finding) Deserialize(b []byte) error {
	if err := json.Unmarshal(b, &f.iamScanner); err != nil {
		return err
	}
	return nil
}
