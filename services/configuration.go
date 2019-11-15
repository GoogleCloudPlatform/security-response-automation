package services

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// Resources represents common resource IDs used for configuration.
type Resources struct {
	FolderIDs      []string `json:"folder_ids"`
	ProjectIDs     []string `json:"project_ids"`
	OrganizationID string   `json:"organization_id"`
}

// CloseBucket contains configuration required for the Cloud Bucket function.
type CloseBucket struct {
	Resources *Resources
	Mode      string
}

// DisableFirewall contains configuration required for the disable firewall function.
type DisableFirewall struct {
	Resources         *Resources
	RemediationAction string   `json:"remediation_action"`
	SourceRanges      []string `json:"source_ranges"`
	Mode              string
}

// RevokeGrants contains configuration required for the Revoke Grants function.
type RevokeGrants struct {
	Resources *Resources
	// A slice of domain names that will be evaluated against incoming added members. If the user
	// matches a domain in this list they will not be removed.
	AllowDomains []string `json:"allow_domains"`
	Mode         string
}

// RemovePublicIP contains configuration required for the remove public IP function.
type RemovePublicIP struct {
	Resources *Resources
	Mode      string
}

// ClosePublicDataset contains configuration required for the close public dataset function.
type ClosePublicDataset struct {
	Resources *Resources
	Mode      string
}

// EnableBucketOnlyPolicy contains configuration required for the enable bucket only policy function.
type EnableBucketOnlyPolicy struct {
	Resources *Resources
	Mode      string
}

// EnableAuditLogs configuration required to enable data access audit logs
type EnableAuditLogs struct {
	Resources *Resources
	Mode      string
}

// CloseCloudSQL contains configuration required for the close Cloud SQL function.
type CloseCloudSQL struct {
	Resources *Resources
	Mode      string
}

// CloudSQLRequireSSL contains configuration required for the Cloud SQL require SSL function.
type CloudSQLRequireSSL struct {
	Resources *Resources
	Mode      string
}

// DisableDashboard contains configuration required for the disable dashboard function.
type DisableDashboard struct {
	Resources *Resources
	Mode      string
}

// CreateSnapshot contains configuration required for the create snapshot function.
type CreateSnapshot struct {
	TargetSnapshotProjectID string   `json:"snapshot_project_id"`
	TargetSnapshotZone      string   `json:"snapshot_zone"`
	TurbiniaProjectID       string   `json:"turbinia_project_id"`
	TurbiniaZone            string   `json:"turbinia_zone"`
	TurbiniaTopicName       string   `json:"turbinia_topic_name"`
	OutputDestinations      []string `json:"output_destinations"`
	Mode                    string
}

// UpdatePassword contains configuration required for the update password function.
type UpdatePassword struct {
	Resources *Resources
	Mode      string
}

// RemoveNonOrgMembers contains configuration required for remove non-org members function.
type RemoveNonOrgMembers struct {
	Resources    *Resources
	AllowDomains []string `json:"allow_domains"`
	Mode         string
}

// Configuration contains the ID(s) to apply actions to.
type Configuration struct {
	CloseBucket            *CloseBucket            `json:"close_bucket"`
	RevokeGrants           *RevokeGrants           `json:"revoke_grants"`
	DisableFirewall        *DisableFirewall        `json:"open_firewall"`
	RemovePublicIP         *RemovePublicIP         `json:"remove_public_ip"`
	ClosePublicDataset     *ClosePublicDataset     `json:"close_public_dataset"`
	CloseCloudSQL          *CloseCloudSQL          `json:"close_cloud_sql"`
	CloudSQLRequireSSL     *CloudSQLRequireSSL     `json:"cloud_sql_require_ssl"`
	DisableDashboard       *DisableDashboard       `json:"disable_dashboard"`
	EnableBucketOnlyPolicy *EnableBucketOnlyPolicy `json:"enable_bucket_only_policy"`
	EnableAuditLogs        *EnableAuditLogs        `json:"enable_audit_logs"`
	CreateSnapshot         *CreateSnapshot         `json:"create_snapshot"`
	UpdatePassword         *UpdatePassword         `json:"cloud_sql_update_password"`
	RemoveNonOrgMembers    *RemoveNonOrgMembers    `json:"remove_non_org_members"`
}

// NewConfiguration returns a new configuration.
func NewConfiguration(file string) (*Configuration, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	c := &Configuration{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}
