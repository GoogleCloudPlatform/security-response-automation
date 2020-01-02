# Security Response Automation

Take automated actions on your Cloud Security Command Center findings:

- Automatically create disk snapshots to enable forensic investigations.
- Revoke IAM grants that violate your desired policy.
- Notify other systems such as PagerDuty, Slack or email.
- See the full list of [automations](/automations.md) for more information.

You're in control:

- Service account runs with lowest permission needed granted at granularity you specify.
- You control which projects are enforced by each automation.
- Every action is logged to StackDriver and is easily auditable.
- Can be run in monitor mode where actions are logged only.

## Configure automations

Before installation we'll configure our automations, copy `./cloudfunctions/router/empty-config.yaml` to `./cloudfunctions/router/config.yaml`. Within this file we'll define a few steps to get started:

- Which automations should apply to which findings.
- Which projects to target these automations with.
- Which projects to exclude.
- Enable/disable dry run(monitor) mode
- Fill in any needed variables.

Every automation has a configuration similar to the following example:

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
            - organizations/1234567891011/folders/424242424242/*
            - organizations/1234567891011/projects/applied-project
          excludes:
            - organizations/1234567891011/folders/424242424242/projects/non-applied-project
            - organizations/1234567891011/folders/565656565656/*
          properties:
            dry_run: true
            allow_domains:
              - foo.com
```

The first important parameter is the finding source type. Currently Security Response Automation supports two types: Security Health Analytics (`sha`) and  Event Threat Detection (`etd`).

Below the finding source type you can add multiple automations, each with its own action to be done, their list of projects or folders that will or will not be affected (`target` and `exclude`) and their properties. In this example we  configured this automation to Event Threat Detection's Anomalous IAM Grant findings under the action name `revoke_iam`.

The `target` and `exclude` arrays accepts an ancestry pattern that is compared against the incoming project. In the above example you have a folder `424242424242` that contains sensitive projects that you want to enforce. However your developers use folder ID `565656565656` that you want to leave alone. If you have projects outside of folders you can specify them too like the `applied-project`.

The last part are the properties. For default all automations have at least the `dry_run` mode that can let you generate StackDriver logs to see what actions it would have taken. The best practice is to run with `dry_run` enabled, because you can confirm the actions as expected before executing them. After that you can set `dry_run` to `false` and redeploy.

The above example introduces an specific example of another property, the `allow_domains`. It is used to ensure that this automation only removes domains not explicitly allowed. To see examples of how to configure the other automations access the
[automations](/automations.md) documentation.

## Configuring permissions

The service account is configured separately within [main.tf](/main.tf). Here we inform Terraform which folders we're enforcing so the required roles are automatically granted. You have a few choices for how to configure this step:

- **Recommended** Specify a list of folder IDs that SRA could grant its service account the necessary roles to. This ensures SRA only has the access it needs at the folders where it's being used. This list will be asked below in the **Installation** section.
- Grant permissions on your own either per project or at the organizational level.

## Forward findings to Pub/Sub

Currently Event Threat Detection publishes to StackDriver and Security Command Center, Security Health Analytics publishes to Security Command Center only. We're currently in the process of moving to Security Command Center notifications but for completeness sake we'll list instructions for StackDriver (legacy) and Security Command Center notifications.

### StackDriver

If you only want to process Event Threat Detection findings, then your configuration is done for you automatically below using Terraform. You can skip the **Set up Security Command Center Notifications** section.

### Set up Security Command Center Notifications

Security Command Center Notifications will enable you to receive Security Health Analytics & Event Threat Detection findings.

Configure Security Command Center notifications

```shell
export PROJECT_ID=<YOUR_AUTOMATION_PROJECT_ID>
export SERVICE_ACCOUNT_EMAIL=automation-service-account@$PROJECT_ID.iam.gserviceaccount.com \
ORGANIZATION_ID=<YOUR_ORGANIZATION_ID> \
TOPIC_ID=threat-findings

gcloud beta organizations add-iam-policy-binding \
$ORGANIZATION_ID \
--member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
--role='roles/securitycenter.notificationConfigEditor'

gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
--member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
--role='roles/pubsub.admin'

go run ./local/cli/main.go \
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

gcloud beta pubsub topics add-iam-policy-binding projects/$PROJECT_ID/topics/$TOPIC_ID \
--member="serviceAccount:service-459837319394@gcp-sa-scc-notification.iam.gserviceaccount.com" \
--role="roles/pubsub.publisher"

gcloud organizations remove-iam-policy-binding $ORGANIZATION_ID \
--member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
--role='roles/pubsub.admin'
```

## Installation

Following these instructions will deploy all automations. Before you get started be sure
you have:

- Go version 1.11
- Terraform version 0.12.17

```shell
gcloud auth application-default login
terraform init

// Install all automations.
terraform apply

// Install a single automation.
terraform apply --target module.revoke_iam_grants
```

These are the available automations modules:

- module.router
- module.close_public_bucket
- module.enable_bucket_only_policy
- module.revoke_iam_grants
- module.create_disk_snapshot
- module.open_firewall
- module.remove_public_ip
- module.close_public_dataset
- module.close_public_cloud_sql
- module.cloud-sql-require-ssl
- module.disable_dashboard
- module.update_password
- module.enable_audit_logs

You **must** deploy `module.router` to be able to process Security Command Center notifications

**NOTE**:

If you set up Security Command Center notifications, you need to remove the StackDriver export so that automations are not triggered twice. To do this, run:

```shell
gcloud logging sinks delete sink-threat-findings --project=$PROJECT_ID
```

TIP: Instead of entering variables every time you can create `terraform.tfvars`
file and input key value pairs there, i.e.
`automation-project="aerial-jigsaw-235219"`.

If at any point you want to revert the changes we've made just run `terraform destroy .`

### Reinstalling a Cloud Function

Terraform will create or destroy everything by default. To redeploy a single Cloud Function you can do:

```shell
// revoke_iam_grants is the name of the Terraform module in `./main.tf`.
// IAMRevoke is the exported Cloud Function name in `exec.go`.
scripts/deploy.sh revoke_iam_grants IAMRevoke $PROJECT_ID
```

### Logging

Each Cloud Function logs its actions to the below log location. This can be accessed by visiting
StackDriver and clicking on the arrow on the right hand side then 'Convert to advanced filter'.
Then paste in the below filter making sure to change the project ID to the project where your
Cloud Functions are installed.
