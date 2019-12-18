### Google Cloud Storage

#### Remove public access

Removes public access from Google Cloud Storage buckets.

Configuration

- Action name `close_bucket`

#### Enable bucket only policy

Enable [Bucket Policy Only](https://cloud.google.com/storage/docs/bucket-policy-only) in Google Cloud Storage buckets.

Configuration

- Action name `enable_bucket_only_policy`

### IAM

#### Revoke IAM grants

Removes members from an IAM policy.

Configuration

- Action name `iam_revoke`

Before a user is removed the user is checked against the below lists. These lists are meant to be mutually exclusive however this is not enforced. These lists allow you to specify exactly what domain names are disallowed or conversely which domains are allowed.

- `allow_domains` An array of strings containing domain names to be matched. If the member added matches a domain in this list do not remove it. At least one domain is required in this list.

**Remove non-Organization members**

Automatically removes non-organization users.

Configuration

- Configured in settings.json under the `remove_non_org_members` key.
- See general [resource list](/README.md#resources) options.
- `allow_domains` whitelist domains to be compared with organization to avoid some members removal.

### Google Compute Engine

#### Create Snapshot

Automatically create a snapshot of all disks associated with a GCE instance.

Configuration

- action `gce_create_disk_snapshot`
- `target_snapshot_project_id` Project ID where disk snapshots should be sent to. If outputing to Turbinia this should be the same as `turbinia_project_id`.
- `target_snapshot_project_zone` Zone where disk snapshots should be sent to. If outputing to Turbinia this should be the same as `turbinia_zone`.
- `output` Repeated set of optional output destinations after the function has executed.
  - `turbinia` Will notify Turbinia when a snapshot is created.

Required if output contains `turbinia`:

The below keys are placed under the `turbinia` key:

- `project_id` Project ID where Tubinia is installed.
- `topic_name` Pub/Sub topic where we should notify Turbinia.
- `zone` Zone where Turbinia disks are kept.

#### Remove public IPs from an instance

Removes all public IPs from an instance's network interface.

Configuration

- Action name `remove_public_ip`

#### Open Firewall

Remediate an [Open Firewall](https://cloud.google.com/security-command-center/docs/how-to-remediate-security-health-analytics#open_firewall) rule.

Configuration

- Action name `remediate_firewall`
- `output` Repeated set of optional output destinations after the function has executed.
  - `pagerduty` Will notify PagerDuty when a firewall is remediated.
- `remediation_action`: one of `disable`, `delete` or `update_source_range`
- `source_ranges`: if the `remediation_action` is `UPDATE_RANGE` the list of IP ranges in [CIDR notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) to replace the current `0.0.0.0/0` range.

Required if output contains `pagerduty`:

The below keys are placed under the `pagerduty` key:

- `enabled` indicates that PagerDuty integration is active
- `api_key` A unique API key generated to allow access to PagerDuty API. See PagerDuty [documentation](https://support.pagerduty.com/docs/generating-api-keys)
- `service_id` of the affected service within PagerDuty.
- `from` is the email address that sends the incident. This must be a valid user within PagerDuty.

#### SSH Brute Force

Create a firewall rule to block SSH access from suspicious IPs

Configuration

- Action name `block_ssh`
- `output` Repeated set of optional output destinations after the function has executed.
  - `pagerduty` Will notify PagerDuty when a SSH access from suspicious IPs is blocked.

Required if output contains `pagerduty`:

The below keys are placed under the `pagerduty` key:

- `enabled` indicates that PagerDuty integration is active
- `api_key` A unique API key generated to allow access to PagerDuty API. See PagerDuty [documentation](https://support.pagerduty.com/docs/generating-api-keys)
- `service_id` of the affected service within PagerDuty.
- `from` is the email address that sends the incident. This must be a valid user within PagerDuty.


### Google Kubernetes Engine

#### Disable Kubernetes Dashboard addon

Automatically disable the Kubernetes Dashboard addon.

Configuration

- Configured in settings.json under the `disable_dashboard` key.
- See general [resource list](/README.md#resources) options.

### Google Cloud SQL

#### Close public Cloud SQL instance

Close a public cloud SQL instance.

Configuration

- Action name `close_cloud_sql`

#### Require SSL connection to Cloud SQL

Update Cloud SQL instance to require SSL connections.

Configuration

- Action name `cloud_sql_require_ssl`

#### Update root password

Update the root password of a Cloud SQL instance.

Configuration

- Action name `cloud_sql_update_password`

### BigQuery

#### Close access to a public BigQuery dataset

Removes public access from a BigQuery dataset.

Configuration

- Configured in settings.json under the `close_public_dataset` key.
- See general [resource list](/README.md#resources) options.

## Example

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    etd:
      bad_ip:
        - action: gce_create_disk_snapshot
          target:
            - organizations/000/folders/0001/*
          exclude:
            - organizations/000/folders/0000/projects/000
          properties:
            dry_run: false
            target_snapshot_project_id: aerial-jigsaw-235219
            target_snapshot_zone: us-central1-action
            output:
            turbinia:
              project_id: ae-turbinia
              topic: psq-turbinia-f7be51e9de8c829c-psq
              zone: us-central1-a
      anomalous_iam:
        - action: iam_revoke
          target:
            - organizations/000/folders/0001/*
          exclude:
            - organizations/000/folders/000000000000/*
            - organizations/000/folders/0000/projects/000
          properties:
            dry_run: false
            allow_domains:
              - google.com
      ssh_brute_force:
        - action: block_ssh
          target:
            - organizations/000/folders/0001/*
          properties:
            output:
            dry_run: false
            pagerduty:
              enable: false
              apy_key: actual_apy_key
              service_id: actual_service_id
              from: tom@example.com
    sha:
      public_bucket_acl:
        - action: close_bucket
          target:
            - organizations/000/folders/0001/*
          exclude:
            - organizations/000/folders/0000/projects/000
          properties:
            dry_run: false
      bucket_policy_only_disabled:
        - action: enable_bucket_only_policy
          target:
            - organizations/000/folders/0001/*
          exclude:
            - organizations/000/folders/0000/projects/000
          properties:
            dry_run: false
      public_sql_instance:
        - action: close_cloud_sql
          target:
            - organizations/000/folders/0001/*
          exclude:
            - organizations/000/folders/0000/projects/000
          properties:
            dry_run: false
      ssl_not_enforced:
        - action: cloud_sql_require_ssl
          target:
            - organizations/000/folders/0001/*
          exclude:
            - organizations/000/folders/0000/projects/000
          properties:
            dry_run: false
      sql_no_root_password:
        - action: cloud_sql_update_password
          target:
            - organizations/000/folders/0001/*
          exclude:
            - organizations/000/folders/0000/projects/000
          properties:
            dry_run: false
      public_ip_address:
        - action: remove_public_ip
          target:
            - organizations/000/folders/0001/*
          exclude:
            - organizations/000/folders/0000/projects/000
          properties:
            dry_run: false
      open_firewall:
        - action: remediate_firewall
          target:
            - organizations/000/folders/0001/*
          properties:
            dry_run: false
            remediation_action: delete
            source_ranges:
              - "10.128.0.0/9"
            output:
              - pagerduty
            pagerduty:
              enable: false
              apy_key: actual_apy_key
              service_id: actual_service_id
              from: tom@example.com
      bigquery_public_dataset:
        - action: close_public_dataset
          target:
            - organizations/000/folders/0001/*
          exclude:
            - organizations/000/folders/0000/projects/000
          properties:
            dry_run: false
```
