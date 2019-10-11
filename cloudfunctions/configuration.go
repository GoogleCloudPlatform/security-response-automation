package cloudfunctions

import (
	"context"

	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/pkg/errors"
)

// Configuration contains the ID(s) to apply actions to.
type Configuration struct {
	FoldersIDs     []string
	ProjectIDs     []string
	OrganizationID string

	resource *entities.Resource
}

// NewConfiguration returns a new configuration.
func NewConfiguration(res *entities.Resource) *Configuration {
	return &Configuration{resource: res}
}

// IfProjectInFolders will apply the function if the project ID is within the folder IDs.
func (c *Configuration) IfProjectInFolders(ctx context.Context, projectID string, fn func() error) error {
	if len(c.FoldersIDs) == 0 {
		return nil
	}
	ancestors, err := c.resource.GetProjectAncestry(ctx, projectID)
	if err != nil {
		return errors.Wrap(err, "failed to get project ancestry")
	}
	for _, resource := range ancestors {
		for _, folderID := range c.FoldersIDs {
			if resource != "folders/"+folderID {
				continue
			}
			if err := fn(); err != nil {
				return err
			}
		}
	}
	return nil
}

// IfProjectInFolders will apply the function if the project ID is within the project IDs.
func (c *Configuration) IfProjectInProjects(_ context.Context, _ string, _ func() error) error {
	return nil
}
