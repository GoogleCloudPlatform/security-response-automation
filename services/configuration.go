package services

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// CloseBucket contains configuration required for the Cloud Bucket function.
type CloseBucket struct {
	Target []string
	Ignore []string
	DryRun bool `json:"dry_run"`
}

// DisableFirewall contains configuration required for the disable firewall function.
type DisableFirewall struct {
	Target             []string
	Ignore             []string
	RemediationAction  string   `json:"remediation_action"`
	SourceRanges       []string `json:"source_ranges"`
	DryRun             bool     `json:"dry_run"`
	OutputDestinations []string `json:"output_destinations"`
}

// RevokeGrants contains configuration required for the Revoke Grants function.
type RevokeGrants struct {
	Target []string
	Ignore []string
	// A slice of domain names that will be evaluated against incoming added members. If the user
	// matches a domain in this list they will not be removed.
	AllowDomains []string `json:"allow_domains"`
	DryRun       bool     `json:"dry_run"`
}

// RemovePublicIP contains configuration required for the remove public IP function.
type RemovePublicIP struct {
	Target []string
	Ignore []string
	DryRun bool `json:"dry_run"`
}

// ClosePublicDataset contains configuration required for the close public dataset function.
type ClosePublicDataset struct {
	Target []string
	Ignore []string
	DryRun bool `json:"dry_run"`
}

// EnableBucketOnlyPolicy contains configuration required for the enable bucket only policy function.
type EnableBucketOnlyPolicy struct {
	Target []string
	Ignore []string
	DryRun bool `json:"dry_run"`
}

// EnableAuditLogs configuration required to enable data access audit logs
type EnableAuditLogs struct {
	Target []string
	Ignore []string
	DryRun bool `json:"dry_run"`
}

// CloseCloudSQL contains configuration required for the close Cloud SQL function.
type CloseCloudSQL struct {
	Target []string
	Ignore []string
	DryRun bool `json:"dry_run"`
}

// CloudSQLRequireSSL contains configuration required for the Cloud SQL require SSL function.
type CloudSQLRequireSSL struct {
	Target []string
	Ignore []string
	DryRun bool `json:"dry_run"`
}

// DisableDashboard contains configuration required for the disable dashboard function.
type DisableDashboard struct {
	Target []string
	Ignore []string
	DryRun bool `json:"dry_run"`
}

// CreateSnapshot contains configuration required for the create snapshot function.
type CreateSnapshot struct {
	TargetSnapshotProjectID string   `json:"snapshot_project_id"`
	TargetSnapshotZone      string   `json:"snapshot_zone"`
	TurbiniaProjectID       string   `json:"turbinia_project_id"`
	TurbiniaZone            string   `json:"turbinia_zone"`
	TurbiniaTopicName       string   `json:"turbinia_topic_name"`
	OutputDestinations      []string `json:"output_destinations"`
	DryRun                  bool     `json:"dry_run"`
}

// UpdatePassword contains configuration required for the update password function.
type UpdatePassword struct {
	Target []string
	Ignore []string
	DryRun bool `json:"dry_run"`
}

// RemoveNonOrgMembers contains configuration required for remove non-org members function.
type RemoveNonOrgMembers struct {
	Target       []string
	Ignore       []string
	AllowDomains []string `json:"allow_domains"`
	DryRun       bool     `json:"dry_run"`
}

// PagerDutyConfiguration contains configuration for the PagerDuty client.
type PagerDutyConfiguration struct {
	APIKey  string `json:"api_key"`
	Enabled bool   `json:"enabled"`
	// ServiceID of the affected service within PagerDuty.
	ServiceID string `json:"service_id"`
	// From is the email address that sends the incident. This must be a valid user within PagerDuty.
	From string `json:"from"`
}

// Configuration contains the ID(s) to apply actions to.
type Configuration struct {
	PagerDuty              *PagerDutyConfiguration `json:"pager_duty"`
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
