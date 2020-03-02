# Security Response Automation

Take automated actions on your Security Command Center findings:

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
- Which projects to target these automations with and which to exclude.
- Whether or not run in monitor mode (dry_run) where changes are only logged and not performed.
- Specify per automation configuration properties.

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
            - organizations/1234567891011/folders/424242424242/folders/565656565656/*
          properties:
            dry_run: true
            anomalous_iam:
              allow_domains:
                - foo.com
```

The first parameter represents the finding provider, `sha` (Security Health Analytics) or `etd` (Event Threat Detection).

Each provider lists findings which contain a list of automations to be applied to those findings. In this example we apply the `revoke_iam` automation to Event Threat Detection's Anomalous IAM Grant finding. For a full list of automations and their supported findings see [automations.md](automations.md).

The `target` and `exclude` arrays accepts an ancestry pattern that is compared against the incoming project. The target and exclude patterns are both considered however the excludes takes precedence. The ancestry pattern allows you to specify granularity at the organization, folder and project level.

<table>
  <tr>
   <td>Pattern</td>
   <td>Description</td>
  </tr>
  <tr>
   <td>organizations/123</td>
   <td>All projects under the organization 123</td>
  </tr>
  <tr>
   <td>organizations/123/folders/456/&ast;</td>
   <td>Any project in folder 456 in organization 123</td>
  </tr>
  <tr>
   <td>organizations/123/folders/456/projects/789</td>
   <td>Apply to the project 789 in folder 456 in organization 123</td>
  </tr>
  <tr>
   <td>organizations/123/projects/789</td>
   <td>Apply to the project 789 in organization 123 that is not within a folder</td>
  </tr>
  <tr>
   <td>organizations/123/&ast;/projects/789</td>
   <td>Apply to the project 789 in organization 123 regardless if its in a folder or not</td>
  </tr>
</table>

All automations have the `dry_run` property that allow to see what actions would have been taken. This is recommend to confirm the actions taken are as expected. Once you have confirmed this by viewing logs in StackDriver you can change this property to false then redeploy the automations.

The `allow_domains` property is specific to the iam_revoke automation. To see examples of how to configure the other automations see the full [documentation](/automations.md).

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

The following commands are based on the [official documentation](https://cloud.google.com/security-command-center/docs/how-to-notifications/#create-notification-config) with the steps
to create and configure the Security Command Center Notifications in your organization. Just remember to first install the Security Response Automation and to
use the **correct topic**  `projects/$AUTOMATION_PROJECT_ID/topics/threat-findings`.

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

gcloud alpha scc notifications create sra-notification \
--organization "$ORGANIZATION_ID" \
--description "Notifies for active findings" \
--pubsub-topic projects/$AUTOMATION_PROJECT_ID/topics/$TOPIC_ID \
--event-type FINDING \
--filter "state=\"ACTIVE"\" \
--impersonate-service-account $SERVICE_ACCOUNT_EMAIL

gcloud organizations remove-iam-policy-binding $ORGANIZATION_ID \
--member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
--role='roles/pubsub.admin'
```

## Installation

Following these instructions will deploy all automations. Before you get started be sure
you have the following installed:

- Go version 1.11
- Terraform version 0.12.17

```shell
gcloud auth application-default login
terraform init
terraform apply
```

If you don't want to install all automations you can specify certain automations individually by running `terraform apply --target module.revoke_iam_grants`. The module name for each automation is found in [main.tf](main.tf). Note the `module.router` is required to be installed.

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
