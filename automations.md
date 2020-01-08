# Automations

**Common propeties**

All automations accept a `dry_run` value to ensure no changes are made to your environment. Changes that would have been made are logged to StackDriver. For each below configuration this `dry_run` property will be omitted. Only properties unique to the automation will be listed.

```yaml
properties:
  dry_run: false
```

**action**

The action property is used to map an automation to a finding. For example, if we wanted to remove public access from Google Cloud Storage buckets detected as public from Security Health Analytics we would do the following:

- Below we see the **Remove public access** automation supports `sha` findings of type `public_bucket_acl`. This is the scanner that detects open buckets.
- We then see the automation is referred to by an action name of `close_bucket`.
- We'll add parameter for `sha` then the finding type `public_bucket_acl` then we configure what automations to apply to that finding.
- Putting it altogether would look something like this:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      public_bucket_acl:
        - action: close_bucket
          target:
            - organizations/1037840971520/*
          exclude:
          properties:
            dry_run: false
```

## Google Cloud Storage

### Remove public access

Removes public access from Google Cloud Storage buckets.

Supported findings:

- Provider: `sha` Finding: `public_bucket_acl`

Action name:

- `close_bucket`

### Enable bucket only policy

Enable [Bucket Policy Only](https://cloud.google.com/storage/docs/bucket-policy-only) for Google Cloud Storage buckets.

Supported findings:

- Provider: `sha` Finding: `bucket_policy_only_disabled`

Action name:

- `enable_bucket_only_policy`

## IAM

### Revoke IAM grants

Removes members from an IAM policy.

Supported findings:

- Provider: `etd` Finding: `anomalous_iam`

Action name:

- `iam_revoke`

Before a user is removed the user is checked against the below lists. These lists are meant to be mutually exclusive however this is not enforced. These lists allow you to specify exactly what domain names are disallowed or conversely which domains are allowed.

Configuration settings for this automation are under the `revoke_iam` key:

- `allow_domains`: An array of strings containing domain names to be matched. If the member added matches a domain in this list do not remove it. At least one domain is required in this list.

```yaml
properties:
  dry_run: false
  revoke_iam:
    allow_domains:
      - google.com
```

### Remove non-Organization members

Removes non-organization members from resource level IAM policy.

Supported findings:

- Provider: `sha` Finding: `non_org_members`

Action name:

- `remove_non_org_members`

Before a user is removed, the user is checked against the below lists. These lists are meant to be mutually exclusive however this is not enforced. These lists allow you to specify exactly what domain names are disallowed or conversely which domains are allowed.

Configuration settings for this automation are under the `non_org_members` key:

- `allow_domains`: An array of strings containing domain names to be matched. If the member added matches a domain in this list do not remove it. At least one domain is required in this list.

Example:

```yaml
properties:
  dry_run: false
  non_org_members:
    allow_domains:
      - prod.foo.com
      - google.com
      - foo.com
```

## Google Compute Engine

### Create Snapshot

Automatically create a snapshot of all disks associated with a GCE instance.

Supported findings:

- Provider: `etd` Finding: `bad_ip`

Action name:

- `gce_create_disk_snapshot`

Configuration settings for this automation are under the `gce_create_snapshot` key:

- `target_snapshot_project_id`: Project ID where disk snapshots should be sent to. If outputting to Turbinia this should be the same as `turbinia_project_id`.
- `target_snapshot_project_zone`: Zone where disk snapshots should be sent to. If outputting to Turbinia this should be the same as `turbinia_zone`.
- `output`: Repeated set of optional output destinations after the function has executed. Currently only `turbinia` is supported.

Required if output contains `turbinia`:

The below keys are placed under the `turbinia` key:

- `project_id` Project ID where Tubinia is installed.
- `topic_name` Pub/Sub topic where we should notify Turbinia.
- `zone` Zone where Turbinia disks are kept.

```yaml
properties:
  dry_run: false
  gce_create_snapshot:
    target_snapshot_project_id: target-projectid
    target_snapshot_zone: us-central1-a
    output:
      - turbinia
    turbinia:
      project_id: turbinia-project
      topic: turbinia-topic
      zone: us-central1-a
```

### Remove public IPs from an instance

Removes all public IPs from an instance's network interface.

Supported findings:

- Provider: `sha` Finding: `public_ip_address`

Action name:

- `remove_public_ip`

### Remediate Firewall

Remediate an [open firewall](https://cloud.google.com/security-command-center/docs/how-to-remediate-security-health-analytics#open_firewall) rule.

Configuration

Supported findings:

- Provider: `sha` Finding: `open_firewall`
- Provider: `etd` Finding: `ssh_brute_force`

Action name:

- `remediate_firewall`

Configuration settings for this automation are under the `open_firewall` key:

- `remediation_action`: One of `disable`, `delete` or `update_source_range`.
  - `disable` Will disable the firewall, it means it will not delete the firewall but the firewall rule will not be enforced on the network.
  - `delete` Will delete the fire wall rule.
  - `update_source_range` Will use the `source_ranges` to update the source ranges used in the firewall.
- `source_ranges`: If the `remediation_action` is `update_source_range` the list of IP ranges in [CIDR notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) to replace the current `0.0.0.0/0` range.

```yaml
properties:
  dry_run: false
  open_firewall:
    remediation_action: update_source_range
    source_ranges:
      - 10.128.0.0/9
```

## Google Kubernetes Engine

### Disable Kubernetes Dashboard addon

Automatically disable the Kubernetes Dashboard addon.

Supported findings:

- Provider: `sha` Finding: `web_ui_enabled`

Action name:

- `disable_dashboard`

## Google Cloud SQL

### Close public Cloud SQL instance

Close a public cloud SQL instance.

Supported findings:

- Provider: `sha` Finding: `public_sql_instance`

Action name:

- `close_cloud_sql`

### Require SSL connection to Cloud SQL

Update Cloud SQL instance to require SSL connections.

Supported findings:

- Provider: `sha` Finding: `ssl_not_enforced`

Action name:

- `cloud_sql_require_ssl`

### Update root password

Update the root password of a Cloud SQL instance.

Supported findings:

- Provider: `sha` Finding: `sql_no_root_password`

Action name:

- `cloud_sql_update_password`

## BigQuery

### Close access to a public BigQuery dataset

Removes public access from a BigQuery dataset.

Supported findings:

- Provider: `sha` Finding: `bigquery_public_dataset`

Action name:

- `close_public_dataset`
