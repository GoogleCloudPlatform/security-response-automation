package testhelpers

import (
	"strings"

	"google.golang.org/api/cloudresourcemanager/v1"
)

func CreateAncestors(members []string) *cloudresourcemanager.GetAncestryResponse {
	ancestors := []*cloudresourcemanager.Ancestor{}
	// 'members' here looks like a resource string but it's really just an easy way to pass the
	// type and id in a single string easily. Note to leave off the "s" from "folders" which is added
	// downstream.
	for _, m := range members {
		mm := strings.Split(m, "/")
		ancestors = append(ancestors, &cloudresourcemanager.Ancestor{
			ResourceId: &cloudresourcemanager.ResourceId{
				Type: mm[0],
				Id:   mm[1],
			},
		})
	}
	return &cloudresourcemanager.GetAncestryResponse{Ancestor: ancestors}
}
