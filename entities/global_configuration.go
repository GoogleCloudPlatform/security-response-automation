package entities

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

// Configuration contains the ID(s) to apply actions to.
type GlobalConfiguration struct {
	settings *Settings
}

// Settings contains user provided settings.
type Settings struct {
	VirusTotal struct {
		APIKey string `json:"api_key"`
	} `json:"virus_total"`
}

// NewConfiguration returns a new configuration.
func NewGlobalConfiguration(f io.Reader) (*Configuration, error) {
	s := &Settings{}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
	}
	return &Configuration{settings: s}, nil
}

// Valid returns if the configuration has at least something filled out.
func (c *Configuration) Valid() bool {
	return len(c.FoldersIDs) > 0 || len(c.ProjectIDs) > 0 || c.OrganizationID != ""
}
