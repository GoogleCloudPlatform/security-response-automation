package cloudfunctions

import (
	"context"
	"fmt"

	"github.com/googlecloudplatform/threat-automation/entities"
)

// ProjectWithinFolders checks to see if the project is within the given set of folders.
func ProjectWithinFolders(ctx context.Context, projectID string, folderIDs []string, r *entities.Resource, fn func() error) error {
	ancestors, err := r.GetProjectAncestry(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to get project ancestry: %q", err)
	}
	for _, resource := range ancestors {
		for _, folderID := range folderIDs {
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
