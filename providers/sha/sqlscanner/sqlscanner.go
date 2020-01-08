package sqlscanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/removepublic"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/requiressl"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/updatepassword"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
	"github.com/googlecloudplatform/security-response-automation/services"
)

const (
	// hostWildcard matches any MySQL host. Reference: https://cloud.google.com/sql/docs/mysql/users.
	hostWildcard = "%"
	// userName is the MySQL user name that will have their password reset.
	userName = "root"
)

// Finding represents this finding.
type Finding struct {
	sqlScanner *pb.SqlScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.SqlScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	if finding.GetFinding().GetSourceProperties().GetScannerName() != "SQL_SCANNER" {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.sqlScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// RemovePublic returns values for the remove public automation.
func (f *Finding) RemovePublic() *removepublic.Values {
	return &removepublic.Values{
		ProjectID:    f.sqlScanner.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceName: sha.Instance(f.sqlScanner.GetFinding().GetResourceName()),
	}
}

// UpdatePassword returns values for the update password automation.
func (f *Finding) UpdatePassword() (*updatepassword.Values, error) {
	password, err := services.GeneratePassword()
	if err != nil {
		return nil, err
	}
	return &updatepassword.Values{
		ProjectID:    f.sqlScanner.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceName: sha.Instance(f.sqlScanner.GetFinding().GetResourceName()),
		Host:         hostWildcard,
		UserName:     userName,
		Password:     password,
	}, nil
}

// RequireSSL returns values for the require SSL automation.
func (f *Finding) RequireSSL() *requiressl.Values {
	return &requiressl.Values{
		ProjectID:    f.sqlScanner.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceName: sha.Instance(f.sqlScanner.GetFinding().GetResourceName()),
	}
}
