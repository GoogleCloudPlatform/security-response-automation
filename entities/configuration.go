package entities

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
}

// DisableFirewall contains configuration required for the disable firewall function.
type DisableFirewall struct {
	Resources         *Resources
	RemediationAction string   `json:"remediation_action"`
	SourceRanges      []string `json:"source_ranges"`
}

// RevokeGrants contains configuration required for the Revoke Grants function.
type RevokeGrants struct {
	Resources  *Resources
	Removelist []string `json:"remove_list"`
}

// RemovePublicIP contains configuration required for the remove public IP function.
type RemovePublicIP struct {
	Resources *Resources
}

// CloseCloudSQL contains configuration required for the close Cloud SQL function.
type CloseCloudSQL struct {
	Resources *Resources
}

type CloudSQLRequireSSL struct {
	Resources *Resources
}

// Configuration contains the IDs to apply actions to.
type Configuration struct {
	CloseBucket          *CloseBucket          `json:"close_bucket"`
	RevokeGrants         *RevokeGrants         `json:"revoke_grants"`
	DisableFirewall      *DisableFirewall      `json:"disable_firewall"`
	RemovePublicIP       *RemovePublicIP       `json:"remove_public_ip"`
	CloseCloudSQL        *CloseCloudSQL        `json:"close_cloud_sql"`
	CloudSQLRequireSSL   *CloudSQLRequireSSL   `json:"cloud_sql_require_ssl"`
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
