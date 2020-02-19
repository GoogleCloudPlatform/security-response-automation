package iamscanner

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/removenonorgmembers"
)

func TestReadFinding(t *testing.T) {
	const (
		nonOrgMemberFinding = `{
		"finding": {
			"name": "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a",
			"parent": "organizations/1050000000008/sources/1986930501000008034",
			"resourceName": "//cloudresourcemanager.googleapis.com/projects/72300000536",
			"state": "ACTIVE",
			"category": "NON_ORG_IAM_MEMBER",
			"externalUri": "https://console.cloud.google.com/iam-admin/iam?project=test-project",
			"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_non_org_iam_member\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "High",
				"Recommendation": "Go to https://console.cloud.google.com/iam-admin/iam?project=test-project and remove entries for users which are not in your organization (e.g. gmail.com addresses).",
				"ProjectId": "test-project",
				"AssetCreationTime": "2019-02-26T15:41:40.726Z",
				"ScannerName": "IAM_SCANNER",
				"ScanRunId": "2019-10-18T08:30:22.082-07:00",
				"Explanation": "A user outside of your organization has IAM permissions on a project or organization."
			},
			"securityMarks": {
				"name": "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a/securityMarks"
			},
			"eventTime": "2019-10-18T15:30:22.082Z",
			"createTime": "2019-10-18T15:31:58.487Z"
           }
		}`
		nonOrgMemberRemediated = `{
		"finding": {
			"name": "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a",
			"parent": "organizations/1050000000008/sources/1986930501000008034",
			"resourceName": "//cloudresourcemanager.googleapis.com/projects/72300000536",
			"state": "ACTIVE",
			"category": "NON_ORG_IAM_MEMBER",
			"externalUri": "https://console.cloud.google.com/iam-admin/iam?project=test-project",
			"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_non_org_iam_member\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "High",
				"Recommendation": "Go to https://console.cloud.google.com/iam-admin/iam?project=test-project and remove entries for users which are not in your organization (e.g. gmail.com addresses).",
				"ProjectId": "test-project",
				"AssetCreationTime": "2019-02-26T15:41:40.726Z",
				"ScannerName": "IAM_SCANNER",
				"ScanRunId": "2019-10-18T08:30:22.082-07:00",
				"Explanation": "A user outside of your organization has IAM permissions on a project or organization."
			},
			"securityMarks": {
				"name": "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a/securityMarks",
				"marks": {
					"sra-remediated-event-time": "2019-10-18T15:30:22.082Z"
			  	}
			},
			"eventTime": "2019-10-18T15:30:22.082Z",
			"createTime": "2019-10-18T15:31:58.487Z"
           }
		}`
		errorMessage = "remediation ignored! Finding already processed and remediated. Security Mark: \"sra-remediated-event-time: 2019-10-18T15:30:22.082Z\""
	)
	extractedValues := &removenonorgmembers.Values{
		ProjectID: "test-project",
		Mark:      "2019-10-18T15:30:22.082Z",
		Name:      "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a",
	}
	for _, tt := range []struct {
		name           string
		ruleName       string
		values         *removenonorgmembers.Values
		bytes          []byte
		expectedErrMsg string
	}{
		{name: "read", ruleName: "non_org_iam_member", values: extractedValues, bytes: []byte(nonOrgMemberFinding), expectedErrMsg: ""},
		{name: "remediated", ruleName: "", values: nil, bytes: []byte(nonOrgMemberRemediated), expectedErrMsg: errorMessage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if err != nil && err.Error() != tt.expectedErrMsg {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedErrMsg)
			}
			if r != nil {
				values := r.RemoveNonOrgMembers()
				if diff := cmp.Diff(values, tt.values); diff != "" {
					t.Errorf("%q failed, difference:%+v", tt.name, diff)
				}
				if name := r.Name(tt.bytes); name != tt.ruleName {
					t.Errorf("%q got:%q want:%q", tt.name, name, tt.ruleName)
				}
			}
		})
	}
}
