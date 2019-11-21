# Security Response Automation

Setup automated actions to run on your security findings. You can use our predefined functions to auto-remediate findings as they come in or write and customize your own.

- Automatically create a disk snapshot to enable future forensic investigations.
- Revoke IAM grants that violate your desired policy.
- Notify other systems such as Turbinia, PagerDuty, Slack or just send an email.

You can selectively control which resources are enforced by each function. Every action is logged and you can also run in **dry_run** mode where changes are not saved.

## Note

This project is currently under development and is not yet ready for users. Stay tuned! If you do decide to use this library early and have any questions please reach out to tomfitzgerald@google.com for help.

## Getting Started

This repository contains Cloud Functions to take automated actions on findings from Event Threat Detection and Security Health Analytics (SHA). For example, if SHA alerts you that a Google Cloud Storage bucket is open you may want to close it, or perhaps leave it alone if its meant to be public.

### Configuration

Before installation we'll configure our automations, rename or copy `empty-settings.json` to `settings.json`. This is done because `settings.json` is ignored by Git so your changes are kept out of our repository and you don't accidently lose your changes. Within this file we'll restrict our automations to only take actions if the affected resource are within a set of resource IDs we declare. For example, you may want to revoke IAM grants in your development environment but in your prod environment you may want to monitor only.

- For a full list of automations and their individual configurations see [automations](/automations.md).
- For each resource ID (folder, project, or organization) you configure below you'll also need to modify (main.tf)[/main.tf] so Terraform can grant the required permissions.

Each automation that considers resources will support the following resources:

#### Resources

- Project IDs `folder_ids`: Take the action if the affected project ID is within this set.
- Folder IDs `project_ids`: Take the action if the affected project ID has an ancestor of a folder ID within this set.
- Organization ID `organization_id`: Take the action if the affected project ID is within this organization ID.

Each automation will check if it's affected project is within the configured resources and only take an action if there's a match. Setting an `organization_id` in a automation's configuration will allow every project within the organization to affected by that automation.

### Example

In the [automations](/automations.md) documentation we see that this automation is configured in [settings.json](settings.json) under the `revoke_iam` key. Within this key we'll fill out which projects will be enforced, in this example we'll specify a folder along with an allow list of expected domains.

```json
{
  "revoke_grants": {
    "resources": {
      "folder_ids": ["670032686187"],
      "organization_id": "",
      "project_ids": []
    },
    "allow_domains": ["google.com", "googleplex.com"]
  }
}
```

Since we're using folders we'll also want to modify [main.tf](/main.tf) to inform Terraform which folders we're enforcing so the required roles are automatically granted. If you choose you can leave out this step but you must authorize the SRA service account to have the necessary roles to revoke the IAM grants. You could grant the account `Project IAM Admin` role on each project ID you want enforced then add the project IDs to the above `project_ids` key. You could also grant the role at the organization level and enter your organzation ID in the `organization_id`.

```terraform
module "revoke_iam_grants" {
  source = "./terraform/automations/revoke-iam-grants"
  setup  = "${module.google-setup}"
  folder-ids = [
    "670032686187",
  ]
}
```

### Installation

Following these instructions will deploy all automations. Before you get started be sure
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
$ export PROJECT_ID=<YOUR_AUTOMATION_PROJECT_ID>
$ export SERVICE_ACCOUNT_EMAIL=automation-service-account@$PROJECT_ID.iam.gserviceaccount.com \
  ORGANIZATION_ID=<YOUR_ORGANIZATION_ID> \
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

Then visit Cloud Console, Cloud Functions, click the Function name, edit then deploy.

### Test

```shell
$ go test ./...
```

### Logging

Each Cloud Function logs its actions to the below log location. This can be accessed by visiting
StackDriver and clicking on the arrow on the right hand side then 'Convert to advanced filter'.
Then paste in the below filter making sure to change the project ID to the project where your
Cloud Functions are installed.

`logName="projects/{{ project_id }}/logs/security-response-automation"`
