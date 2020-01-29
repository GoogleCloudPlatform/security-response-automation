package loggingscanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/enableauditlogs"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
)

// Finding represents this finding.
type Finding struct {
	loggingscanner *pb.LoggingScanner
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.loggingscanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// Category returns the category of the finding.
func (f *Finding) Category() string {
	if f.loggingscanner.GetFinding().GetSourceProperties().GetScannerName() != "LOGGING_SCANNER" {
		return ""
	}
	return strings.ToLower(f.loggingscanner.GetFinding().GetCategory())
}

// EnableAuditLogs return values for the enable audit logs automation.
func (f *Finding) EnableAuditLogs() *enableauditlogs.Values {
	return &enableauditlogs.Values{
		ProjectID: f.loggingscanner.GetFinding().GetSourceProperties().GetProjectID(),
		Hash:      f.loggingscanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated(),
		Name:      f.loggingscanner.GetFinding().GetName(),
	}
}

// StringToBeHashed returns the string that will be used to generate the mark hash finding.
func (f *Finding) StringToBeHashed() string {
	return f.loggingscanner.GetFinding().GetEventTime() + f.loggingscanner.GetFinding().GetName()
}

// SraRemediated returns the sraRemediate mark of the finding.
func (f *Finding) SraRemediated() string {
	return f.loggingscanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated()
}

// Deserialize deserializes the finding in object.
func (f *Finding) Deserialize(b []byte) error {
	if err := json.Unmarshal(b, &f.loggingscanner); err != nil {
		return err
	}
	return nil
}
