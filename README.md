# Security Response Automation

Take automated actions on your Cloud Security Command Center findings:

- Automatically create disk snapshots to enable forensic investigations.
- Revoke IAM grants that violate your desired policy.
- Notify other systems such as PagerDuty, Slack or email.

See full list of [automations](/automations.md).

You're in control:

- Service account runs with lowest permission needed granted at granularity you specify.
- You control which projects are enforced by each automation. 
- Every action is logged to StackDriver and is easy auditable.
- Can be run in monitor mode where actions are logged only.

### Configure automations

Before installation we'll configure our automations, rename or copy `./router/empty-config.yaml` to `./router/config.yaml`. Within this file we'll restrict our automations to only take actions if the affected resource are within a set of resource IDs we declare. For example, you may want to revoke IAM grants in your development environment but in your prod environment you may want to monitor only.

- For a full list of automations and their individual configurations see [automations](/automations.md).
- For each resource ID (folder, project, or organization) you configure below you'll also need to modify (main.tf)[/main.tf] so Terraform can grant the required permissions.

Each automation that considers resources will support the following resources:

### Example

In the [automations](/automations.md) documentation we see that this automation is configured in [config.yaml](config.yaml) under the `revoke_iam` key. In this example we'll configure Security Response Automation to do the following:

- When Event Threat Detection (ETD) detects an Anomalous IAM Grant take the following set of actions:
  - Call the `iam_revoke` automation
  - Apply this automation to every project under the folder number 1234567890 excluding project 54321.
  - This automation will run in dry_run mode, no users will be removed, however you will see a log of who would have been removed.
  - Do not remove any users who are part of the foo.com domain.

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    etd:
      anomalous_iam:
        - action: iam_revoke
          target:
            - folders/1234567890
          exclude:
            - projects/54321
          properties:
            dry_run: false
            allow_domains:
              - foo.com
```

#### Configuring permissions

The service account is configured separately within [main.tf](/main.tf). Here we inform Terraform which folders we're enforcing so the required roles are automatically granted. If you choose you can leave out this step but you must authorize the SRA service account to have the necessary roles to revoke the IAM grants. You could grant the account `Project IAM Admin` role on each project ID you want enforced then add the project IDs to the above `project_ids` key. You could also grant the role at the organization level and enter your organzation ID in the `organization_id`.

```terraform
module "revoke_iam_grants" {
  source     = "./cloudfunctions/iam/revoke"
  setup      = module.google-setup
  folder-ids = ["670032686187"]
}
```

### Installation

Following these instructions will deploy all automations. Before you get started be sure
you have:

- Go version 1.11
- Terraform version 0.12.17

```shell
$ gcloud auth application-default login
$ terraform init

// Install all automations.
$ terraform apply

// Install a single automations.
$ terraform apply --target module.revoke_iam_grants
```

TIP: Instead of entering variables every time you can create `terraform.tfvars`
file and input key value pairs there, i.e.
`automation-project="aerial-jigsaw-235219"`.

If at any point you want to revert the changes we've made just run `terraform destroy .`

**CSCC Notifications**

Security Health Analytics requires CSCC notifications to be setup. This requires your account to be added to a early access group, please ping tomfitzgerald@google.com to be added. You can then create a new notification config that will send all CSCC findings to a Pub/Sub topic.

Note: If you enable CSCC notifications as described below you'll need to remove the StackDriver export so automations are not triggered twice. You can do this by running:

```shell
$ gcloud logging sinks delete sink-threat-findings --project=$PROJECT_ID
```

Configure CSCC notifications

```shell
$ export PROJECT_ID=<YOUR_AUTOMATION_PROJECT_ID>
$ export SERVICE_ACCOUNT_EMAIL=automation-service-account@$PROJECT_ID.iam.gserviceaccount.com \
  ORGANIZATION_ID=<YOUR_ORGANIZATION_ID> \
  TOPIC_ID=threat-findings

$ gcloud beta organizations add-iam-policy-binding \
	$ORGANIZATION_ID \
	--member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
	--role='roles/securitycenter.notificationConfigEditor'

$ gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
  --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
  --role='roles/pubsub.admin'

$ go run ./local/cli/main.go \
  --command create \
  --org-id=$ORGANIZATION_ID \
  --topic=projects/$PROJECT_ID/topics/$TOPIC_ID

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
$ gcloud beta pubsub topics add-iam-policy-binding projects/$PROJECT_ID/topics/$TOPIC_ID \
  --member="serviceAccount:service-459837319394@gcp-sa-scc-notification.iam.gserviceaccount.com" \
  --role="roles/pubsub.publisher"

$ gcloud organizations remove-iam-policy-binding $ORGANIZATION_ID \
  --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
  --role='roles/pubsub.admin'
```

### Reinstalling a Cloud Function

Terraform will create or destroy everything by default. To redeploy a single Cloud Function you can do:

```shell
// revoke_iam_grants is the name of the Terraform module in `./main.tf`.
// IAMRevoke is the exported Cloud Function name in `exec.go`.
$ scripts/deploy.sh revoke_iam_grants IAMRevoke $PROJECT_ID
```

### Logging

Each Cloud Function logs its actions to the below log location. This can be accessed by visiting
StackDriver and clicking on the arrow on the right hand side then 'Convert to advanced filter'.
Then paste in the below filter making sure to change the project ID to the project where your
Cloud Functions are installed.
