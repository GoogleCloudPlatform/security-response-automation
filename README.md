# Security Response Automation

Take automated actions on your Cloud Security Command Center findings:

- Automatically create disk snapshots to enable forensic investigations.
- Revoke IAM grants that violate your desired policy.
- Notify other systems such as PagerDuty, Slack or email.
- See the full list of [automations](/automations.md) for more information.

You're in control:

- Service account runs with lowest permission needed granted at granularity you specify.
- You control which projects are enforced by each automation.
- Every action is logged to StackDriver and is easy auditable.
- Can be run in monitor mode where actions are logged only.

### Configure automations

Before installation we'll configure our automations, copy `./router/empty-config.yaml` to `./router/config.yaml`. Within this file we'll define a few steps to get started:

- Which automations should apply to which findings.
- Which projects to target these automations with.
- Which projects to exclude.
- Enable/disable dry run(monitor) mode
- Fill in any needed variables.

## Restricting projects

Every automation accepts a `target` and `exclude` array that accepts an ancestry pattern that is compared against the incoming project. For example lets say you have a folder `424242424242` that contains sensitive projects that you want to enforce. However your developers use folder ID `5656565656` that you want to leave alone. If you have projects outside of folders you can specify them too.

In this case your configuration could look like:

```yaml
target:
  - organizations/1234567890/folders/424242424242/*
  - organizations/1234567890/projects/77981237242
excludes:
  - organizations/1234567890/folders/5656565656/*
```

In the [automations](/automations.md) documentation we see that this automation is configured in [config.yaml](config.yaml) under the action name `revoke_iam`. In this example we'll configure Security Response Automation to apply this automation to Event Threat Detection's Anomalous IAM Grant findigns.

It's important to note this automation requires the `allow_domains` to contain at least one valid domain. This is used to ensure SRA only removes domains not explictly allowed. It's also best practice to run SRA with `dry_run` enabled. This way you can let SRA generate StackDriver logs to see what actions it would have taken. Once you confirm this is as expected you can set `dry_run` to false and redeploy.

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
            - organizations/1234567890/folders/424242424242/*
          exclude:
          properties:
            dry_run: false
            allow_domains:
              - foo.com
```

#### Configuring permissions

The service account is configured separately within [main.tf](/main.tf). Here we inform Terraform which folders we're enforcing so the required roles are automatically granted. You have a few choices for how to configure this step:

- **Recommended** Specify a list of folder IDs that SRA could grant its service account the necessary roles to. This ensures SRA only has the access it needs at the folders where it's being used. This list will be asked below in the **Installation** section.
- Grant permissions on your own either per project or at the organizational level.

#### Forward findings to Pub/Sub

Currently Event Threat Detection publishes to StackDriver and Security Command Center, Security Health Analytics publishes to Security Command Center only. We're currently in the process of moving to Security Command Center notifications but for completeness sake we'll list instructions for StackDriver (legacy) and Security Command Center notifications.

**StackDriver**

If you only want to process Event Threat Detection findings, then your configuration is done for you automatically below using Terraform. You can skip the **Set up Security Command Center Notifications** section, and continue to **Configure Security Command Center Notifications**.

**Set up Security Command Center Notifications**

Security Command Center Notifications will enable you to receive Security Health Analytics & Event Threat Detection findings. 

Configure Security Command Center notifications

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

**NOTE**

If you set up Security Command Center notifications, you need to remove the StackDriver export so that automations are not triggered twice. To do this, run:

```shell
$ gcloud logging sinks delete sink-threat-findings --project=$PROJECT_ID
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
$ scripts/deploy.sh revoke_iam_grants IAMRevoke $PROJECT_ID
```

### Logging

Each Cloud Function logs its actions to the below log location. This can be accessed by visiting
StackDriver and clicking on the arrow on the right hand side then 'Convert to advanced filter'.
Then paste in the below filter making sure to change the project ID to the project where your
Cloud Functions are installed.
