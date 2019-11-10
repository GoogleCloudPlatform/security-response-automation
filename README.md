# Security Response Automation

Cloud Functions to take automated actions on threat and vulnerability findings.

## Note

This project is currently under development and is not yet ready for users. Stay tuned! If you do decide to use this library early and have any questions please reach out to tomfitzgerald@google.com for help.

## Getting Started

This repository contains Cloud Functions to take automated actions on findings from Event Threat Detection and Security Health Analytics (SHA). For example, if SHA alerts you that a Google Cloud Storage bucket is open you may want to close it, or perhaps leave it alone if its meant to be public. The logic and the framework to express such automation is the purpose of SRA!

### Configuration

Before installation we'll configure our Cloud Functions in `settings.json`. Within this file we'll restrict our Functions to only take actions if the affected resource is within a set of resource IDs.

For each resource ID (folder, project, or organization) you configure below you'll also need to modify (main.tf)[/main.tf] so Terraform can grant the required permissions.

Each Function that considers resources will support the following resources:

#### Resources

- Project IDs `folder_ids`: The Function will execute if the affected project ID is within this set.
- Folder IDs `project_ids`: Take the action if the affected project ID has an ancestor of a folder ID within this set.
- Organization ID `organization_id`: Take the action if the affected project ID is within this organization ID.

Each function will check if it's affected project is within the configured resources and only take an action if there's a match. Setting an `organization_id` in a Function's configuration will allow every project within the organization to affected by that Function.

### Google Cloud Storage

#### Remove public access

Removes public access from Google Cloud Storage buckets.

Configuration

- Configured in settings.json under the `close_bucket` key.
- See general [resource list](#resources) options.

#### Enable bucket only policy

Enable [Bucket Policy Only](https://cloud.google.com/storage/docs/bucket-policy-only) in Google Cloud Storage buckets.

Configuration

- Configured in settings.json under the `enable_bucket_only_policy` key.
- See general [resource list](#resources) options.

### IAM

#### Revoke IAM grants

Removes members from an IAM policy.

Configuration

This Cloud Function will automatically remove public IPs found by Security Health Analytics that match the criteria you specify.
Depending on which resources you specify will determine which projects are enforced.

- Configured in settings.json under the `revoke_iam` key.
- See general [resource list](#resources) options.
- `remove_list` An array of strings containing domain names to be matched against the members added. This is an additional check made before removing a user, after a resource is matched the member's domain but must be in this list to be removed.

### Google Compute Engine

#### Create Snapshot

Automatically create a snapshot of all disks associated with a GCE instance.

Configuration

- Configured in settings.json under the `create_snapshot` key.
- `snapshot_project_id` Optional project ID where disk snapshots should be sent to. If outputing to Turbinia this should be the same as `turbinia_project_id`.
- `snapshot_zone` Optional zone where disk snapshots should be sent to. If outputing to Turbinia this should be the same as `turbinia_zone`.
- `output_destinations` Repeated set of optional output destinations after the function has executed.
  - `turbinia` Will notify Turbinia when a snapshot is created.

Required if output contains `turbinia`:

- `turbinia_project_id` Project ID where Tubinia is installed.
- `turbinia_topic_name` Pub/Sub topic where we should notify Turbinia.
- `turbinia_zone` Zone where Turbinia disks are kept.

#### Remove public IPs from an instance

Removes all public IPs from an instance's network interface.

Configuration

- Configured in settings.json under the `remove_public_ip` key.
- See general [resource list](#resources) options.

#### Remediate open firewall

Remediate an [Open Firewall](https://cloud.google.com/security-command-center/docs/how-to-remediate-security-health-analytics#open_firewall) rule.

Configuration

- Configured in settings.json under the `disable_firewall` key.
- See general [resource list](#resources) options.
- `remediation_action`: one of `DISABLE`, `DELETE` or `UPDATE_RANGE`
- `source_ranges`: if the `remediation_action` is `UPDATE_RANGE` the list of IP ranges in [CIDR notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) to replace the current `0.0.0.0/0` range.

### Google Kubernetes Engine

#### Disable Kubernetes Dashboard addon

Automatically disable the Kubernetes Dashboard addon.

Configuration

- Configured in settings.json under the `disable_dashboard` key.
- See general [resource list](#resources) options.

### Google Cloud SQL

#### Close public Cloud SQL instance

Close a public cloud SQL instance.

Configuration

- Configured in settings.json under the `close_cloud_sql` key.
- See general [resource list](#resources) options.

#### Require SSL connection to Cloud SQL

Update Cloud SQL instance to require SSL connections.

Configuration

- Configured in settings.json under the `cloud_sql_require_ssl` key.
- See general [resource list](#resources) options.

### Installation

Following these instructions will deploy all SRA Cloud Functions. Before you get started be sure
you have (at least) **Go version 1.11 installed**.

```shell
$ gcloud auth application-default login
$ terraform init

// Install all Functions.
$ terraform apply

// Install a single Function.
$ terraform apply --target module.revoke_iam_grants
```

TIP: Instead of entering variables every time you can create `terraform.tfvars`
file and input key value pairs there, i.e.
`automation-project="aerial-jigsaw-235219"`.

If at any point you want to revert the changes we've made just run `terraform destroy .`

**CSCC Notifications**

Security Health Analytics requires CSCC notifications to be setup. This requires your account to be added to a early access group, please ping tomfitzgerald@google.com to be added. You can then create a new notification config that will send all CSCC findings to a Pub/Sub topic.

```shell
$ export PROJECT_ID=ae-threat-detection
$ export SERVICE_ACCOUNT_EMAIL=automation-service-account@$PROJECT_ID.iam.gserviceaccount.com \
  ORGANIZATION_ID=154584661726 \
  TOPIC_ID=cscc-notifications-topic

$ gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
  --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
  --role='roles/pubsub.admin'

$ go run ./local/cli/main.go \
  --command create \
  --org-id=$ORGANIZATION_ID \
  --topic=projects/$PROJECT_ID/topics/cscc-notifications-topic12w

// Note the output, specifically the generated `service_acount`:
//
// 2019/11/07 14:06:00 New NotificationConfig created: \
// name:"organizations/1037840971520/notificationConfigs/sampleConfigId"
// description:"Notifies active findings"
// event_type:FINDING pubsub_topic:"projects/ae-threat-detection/topics/cscc-notifications-topic"
// service_account:"service-459837319394@gcp-sa-scc-notification.iam.gserviceaccount.com"
// streaming_config:<filter:"state = \"ACTIVE\"" >
//
// Make sure to replace `SERVICE_ACCOUNT_FROM_ABOVE` with the generated service account.
gcloud beta pubsub topics add-iam-policy-binding projects/$PROJECT_ID/topics/$TOPIC_ID \
  --member="serviceAccount:<SERVICE_ACCOUNT_FROM_ABOVE>" \
  --role="roles/pubsub.publisher"

gcloud organizations remove-iam-policy-binding $ORGANIZATION_ID \
  --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
  --role='roles/pubsub.admin'
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
