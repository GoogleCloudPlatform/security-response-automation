# Security Response Automation

Cloud Functions to take automated actions on threat and vulnerability findings.

## Note

This project is currently under development and is not yet ready for users. Stay tuned! If you do decide to use this library early and have any questions please reach out to tomfitzgerald@google.com for help.

## Getting Started

This repository contains Cloud Functions to take automated actions on findings from Event Threat Detection and Security Health Analytics (SHA). For example, if SHA alerts you that a Google Cloud Storage bucket is open you may want to close it, or perhaps leave it alone if its meant to be public. The logic and the framework to express such automation is the purpose of SRA!

### Configuration

Before we install we'll want to configure our Cloud Functions which is done within settings.json. In the current setup we'll need to provision the SRA service account to have the appropriate permissions required to take the below actions.

** NOTE: At this time only folder IDs are supported. **

**Close open buckets**

This Cloud Function will automatically close public buckets found by Security Health Analytics that match the criteria you specify. Depending on which resources you specify will determine which projects are enforced.

- `folder_ids` If the bucket is in a project under a folder within this set the bucket will be closed.
- `project_ids` If the bucket is in a project that is within this set the bucket will be closed.
- `organization_id` Any bucket found within this organization will be automatically closed.

For example, if you wanted to only close buckets in the folder **development** you'll want to find that folders ID in [Cloud Resource Manager](https://console.cloud.google.com/cloud-resource-manager) and place into the `folder_ids` array.

```json
{
  "close_bucket": {
    "resources": {
      "folder_ids": ["670032686187"]
    }
  }
}
```

**Revoke IAM grants**

This Cloud Function responds to Event Threat Detection's Anomalous IAM grant detector sub rule, external account added sub-rule. Within this configuration you can specify a list of domain names that you wish to disable. This way you can control which members are removed.

- `remove_list` An array of strings containing domain names to be matched against the members added. If there is a match, the member will be removed from the resource if that are within the below resources.
- `folder_ids` If the member is added to a project that matches the above domain list and within a folder within this array then remove.
- `project_ids` Same logic as above but uses project IDs.
- `organization_id` Any member granted to a project within this organization will be removed.

```json
{
  "revoke_grants": {
    "resources": {
      "folder_ids": ["670032686187"]
    },
    "remove_list": ["gmail.com"]
  }
}
```

**Remove Public IPs from GCE Instance**

This Cloud Function will automatically remove public IPs found by Security Health Analytics that match the criteria you specify.
Depending on which resources you specify will determine which projects are enforced.

- `folder_ids` If the instance is in a project under a folder within this set the public access will be removed.
- `project_ids` If the instance is in a project that is within this set the public access will be removed.
- `organization_id` Any instance found with public access within this organization will have the public access removed.

For example, if you wanted to only remove public access in the folder **development** you'll want to find that folders ID in [Cloud Resource Manager](https://console.cloud.google.com/cloud-resource-manager) and place into the `folder_ids` array.

```json
{
  "remove_public_ip": {
    "resources": {
      "folder_ids": ["670032686187"]
    }
  }
}
```

**Disable Kubernetes Dashboard addon**

This Cloud Function will automatically disable Kubernetes Dashboard addon found by Security Health Analytics.
Depending on which resources you specify will determine which projects are enforced.

- `folder_ids` If the cluster is in a project under a folder within this set the Kubernetes Dashboard addon will be disabled.
- `project_ids` If the cluster is in a project that is within this set the Kubernetes Dashboard addon will be disabled.
- `organization_id` Any cluster found within this organization will have Kubernetes Dashboard addon disabled.

```json
{
  "disable_dashboard": {
    "resources": {
      "folder_ids": ["670032686187"]
    }
  }
}
```

**Enable bucket only IAM policy**

This Cloud Function will automatically enable the [Bucket Only policy](https://cloud.google.com/storage/docs/bucket-policy-only) on the selected bucket.
Depending on which resources you specify it will determine which projects are enforced.

- `folder_ids` If the bucket is in a project under a folder within this set the bucket only IAM policy will be enabled.
- `project_ids` If the bucket is in a project that is within this set the bucket only IAM policy will be enabled.

For example, if you want to only enable bucket only IAM policy in the folder **development**
you'll want to find that folders ID in [Cloud Resource Manager](https://console.cloud.google.com/cloud-resource-manager)
and place into the `folder_ids` array.

```json
{
  "enable_bucket_only_policy": {
    "resources": {
      "folder_ids": [
        "670032686187"
      ]
    }
  }
}
```

**Remove non-Organization members**

This Cloud Function will automatically remove non-organization members when occurrence found by Security Health Analytics, so the Cloud IAM policy is updated accordingly.
There's the option to enable/disable this execution and create an organization whitelist to avoid members removal.

Current implementation consider only Google account (`user:`) members, i.e. service account (`serviceAccount:`), GSuite or Cloud identity domain (`domain:`) and Google group  `groups:` are not covered yet

Configured in settings.json under the `remove_non_org_members` key.

### Installation

Following these instructions will deploy all SRA Cloud Functions.

```shell
$ gcloud auth application-default login
$ terraform init
$ terraform apply
```

TIP: Instead of entering variables every time you can create `terraform.tfvars`
file and input key value pairs there, i.e.
`automation-project="aerial-jigsaw-235219"`.

If at any point you want to revert the changes we've made just run `terraform destroy .`

**CSCC Notifications**

Security Health Analytics requires CSCC notifications to be setup. This requires your account to be added to a early access group, please ping tomfitzgerald@google.com to be added. You can then create a new notification config that will send all CSCC findings to a Pub/Sub topic.

```shell
$ export SERVICE_ACCOUNT_EMAIL=automation-service-account@aerial-jigsaw-235219.iam.gserviceaccount.com \
  ORGANIZATION_ID=154584661726 \
  PROJECT_ID=aerial-jigsaw-235219 \
  TOPIC_ID=cscc-notifications-topic

$ ./enable-cscc-notfications.sh
```

### Reinstalling a Cloud Function

Terraform will create or destroy everything by default. To redeploy a single Cloud Function you can do:

```shell
$ zip -r ./deploy/functions.zip . -x *deploy* -x *.git* -x *.terraform*
$ terraform apply .
```

Then visit Cloud Console, Cloud Functions, click the Function name then edit. Finally hit deploy.

### Test

```shell
$ go test ./...
```

## CSCC notifications setup

- Need to grant automation account the proper permissions. Below example shown if adding via the
  config service account. Note the granting account must have organization admin to grant this
  role.
- Make sure to edit `enable-cscc-notifications.sh` and fill in your variables to match your
  environment.

```shell
./enable-cscc-notifications.sh
```

### Logging

Each Cloud Function logs its actions to the below log location. This can be accessed by visiting
StackDriver and clicking on the arrow on the right hand side then 'Convert to advanced filter'.
Then paste in the below filter making sure to change the project ID to the project where your
Cloud Functions are installed.

`logName="projects/{{ project_id }}/logs/security-response-automation"`
