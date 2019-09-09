// package main

// import (
// 	"fmt"

// 	"github.com/GoogleCloudPlatform/threat-automation/automation/actions"
// 	"github.com/GoogleCloudPlatform/threat-automation/automation/clients"

// 	"context"

// 	"cloud.google.com/go/pubsub"
// )

// var (
// 	// folderID specifies which folder RevokeExternalGrantsFolders should remove members from.
// 	folderIDs = []string{"670032686187"}
// 	// disallowed contains a list of external domains RevokeExternalGrantsFolders should remove.
// 	disallowed = []string{"test.com", "gmail.com"}
// )

// func main() {
// 	ctx := context.Background()
// 	m := &pubsub.Message{}
// 	// m.Data = []byte(`{"insertId":"ujacyda6","jsonPayload":{"affectedResources":[{"gcpResourceName":"//cloudresourcemanager.googleapis.com/projects/997507777601"}],"detectionCategory":{"indicator":"domain","ruleName":"bad_domain","technique":"cryptojacking"},"detectionPriority":"HIGH","eventTime":"2019-08-30T18:08:29.923Z","evidence":[{"sourceLogId":{"insertId":"1lfp54jg5g7m31j","timestamp":"2019-08-30T18:08:29.638689943Z"}}],"properties":{"sourceInstance":  "/projects/aerial-jigsaw-235219/zones/us-central1-c/instances/instance-2", "destIp":"136.243.102.167","destPort":80,"direction":"OUTGOING","domain":["aeon.pool.minergate.com","ltc.pool.minergate.com"],"ip":["88.99.142.163","94.130.143.162","136.243.102.167"],"location":"us-central1-c","project_id":"aerial-jigsaw-235219","protocol":6,"srcIp":"10.128.0.2","srcPort":51250,"subnetwork_id":"288355645352614400","subnetwork_name":"default"},"sourceId":{"customerOrganizationNumber":"154584661726","projectNumber":"997507777601"}},"logName":"projects/aerial-jigsaw-235219/logs/threatdetection.googleapis.com%2Fdetection","receiveTimestamp":"2019-08-30T18:08:30.949798075Z","resource":{"labels":{"detector_name":"bad_domain","project_id":"aerial-jigsaw-235219"},"type":"threat_detector"},"severity":"CRITICAL","timestamp":"2019-08-30T18:08:29.923Z"}`)
// 	in := `{
// 		"insertId": "31y1f6a4",
// 		"jsonPayload": {
// 		  "affectedResources": [
// 			{
// 			  "gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/997507777601"
// 			}
// 		  ],
// 		  "detectionCategory": {
// 			"indicator": "audit_log",
// 			"ruleName": "iam_anomalous_grant",
// 			"subRuleName": "external_member_added_to_policy",
// 			"technique": "persistence"
// 		  },
// 		  "detectionPriority": "HIGH",
// 		  "eventTime": "2019-09-09T18:25:49.236Z",
// 		  "evidence": [
// 			{
// 			  "sourceLogId": {
// 				"insertId": "-kt3q87c71s",
// 				"timestamp": "2019-09-09T18:25:47.409Z"
// 			  }
// 			}
// 		  ],
// 		  "properties": {
// 			"bindingDeltas": [
// 			  {
// 				"action": "ADD",
// 				"member": "user:ccexperts@gmail.com",
// 				"role": "roles/editor"
// 			  }
// 			],
// 			"externalMembers": [
// 			  "user:ccexperts@gmail.com"
// 			],
// 			"principalEmail": "tom3fitzgerald@gmail.com",
// 			"project_id": "aerial-jigsaw-235219"
// 		  },
// 		  "sourceId": {
// 			"customerOrganizationNumber": "154584661726",
// 			"projectNumber": "997507777601"
// 		  }
// 		},
// 		"logName": "projects/aerial-jigsaw-235219/logs/threatdetection.googleapis.com%2Fdetection",
// 		"receiveTimestamp": "2019-09-09T18:25:50.087113103Z",
// 		"resource": {
// 		  "labels": {
// 			"detector_name": "iam_anomalous_grant",
// 			"project_id": "aerial-jigsaw-235219"
// 		  },
// 		  "type": "threat_detector"
// 		},
// 		"severity": "CRITICAL",
// 		"timestamp": "2019-09-09T18:25:49.236Z"
// 	  }`

// 	m.Data = []byte(in)
// 	c := clients.New()

// 	fmt.Println("init")
// 	fmt.Printf("\n%+q", in)
// 	if err := c.Initialize(); err != nil {
// 		fmt.Printf("client initialize failed: %q", err)
// 		return
// 	}
// 	fmt.Println("init cc")
// 	ids := []string{"670032686187"}
// 	disallowed := []string{"gmail.com"}
// 	if err := actions.RevokeExternalGrantsFolders(ctx, *m, c, ids, disallowed); err != nil {
// 		fmt.Printf("fail %s", err)
// 		return
// 	}
// 	fmt.Println("done")
// }
