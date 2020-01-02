# Automation Modules

## Google Cloud Storage

### Remove public access

Removes public access from Google Cloud Storage buckets.

Configuration

- Finding source type: `sha`

- Finding: `public_bucket_acl`

- Action name: `close_bucket`

Properties:

```yaml
properties:
  dry_run: false
```

### Enable bucket only policy

Enable [Bucket Policy Only](https://cloud.google.com/storage/docs/bucket-policy-only) in Google Cloud Storage buckets.

Configuration

- Finding source type: `sha`

- Finding: `bucket_policy_only_disabled`

- Action name: `enable_bucket_only_policy`

Properties:

```yaml
properties:
  dry_run: false
```

## IAM

### Revoke IAM grants

Removes members from an IAM policy.

Configuration

- Finding source type: `etd`

- Finding: `anomalous_iam`

- Action name: `iam_revoke`

Before a user is removed the user is checked against the below lists. These lists are meant to be mutually exclusive however this is not enforced. These lists allow you to specify exactly what domain names are disallowed or conversely which domains are allowed.

Properties:

- `allow_domains`: An array of strings containing domain names to be matched. If the member added matches a domain in this list do not remove it. At least one domain is required in this list.

```yaml
properties:
  dry_run: false
  allow_domains:
    - google.com
```

### Remove non-Organization members

Removes non-organization members from resource level IAM policy.

Configuration

- Finding source type: `sha`

- Finding: `non_org_members`

- Action name: `remove_non_org_members`

Before a user is removed, the user is checked against the below lists. These lists are meant to be mutually exclusive however this is not enforced. These lists allow you to specify exactly what domain names are disallowed or conversely which domains are allowed.

Properties:

- `allow_domains`: An array of strings containing domain names to be matched. If the member added matches a domain in this list do not remove it. At least one domain is required in this list.

Example:

```yaml
properties:
  dry_run: false
  allow_domains: ["prod.foo.com", "google.com", "foo.com"]
```

## Google Compute Engine

### Create Snapshot

Automatically create a snapshot of all disks associated with a GCE instance.

Configuration

- Finding source type: `etd`

- Finding: `bad_ip`

- action `gce_create_disk_snapshot`

Properties:

- `target_snapshot_project_id`: Project ID where disk snapshots should be sent to. If outputting to Turbinia this should be the same as `turbinia_project_id`.
- `target_snapshot_project_zone`: Zone where disk snapshots should be sent to. If outputting to Turbinia this should be the same as `turbinia_zone`.
- `output`: Repeated set of optional output destinations after the function has executed.
- `turbinia` Will notify Turbinia when a snapshot is created.

Required if output contains `turbinia`:

The below keys are placed under the `turbinia` key:

- `project_id` Project ID where Tubinia is installed.
- `topic_name` Pub/Sub topic where we should notify Turbinia.
- `zone` Zone where Turbinia disks are kept.

```yaml
properties:
  dry_run: false
  target_snapshot_project_id: target-projectid
  target_snapshot_zone: us-central1-a
  output:
  turbinia:
    project_id: turbinia-project
    topic: turbinia-topic
    zone: us-central1-a
```

### Remove public IPs from an instance

Removes all public IPs from an instance's network interface.

Configuration

- Finding source type: `sha`

- Finding: `public_ip_address`

- Action name `remove_public_ip`

Properties:

```yaml
properties:
  dry_run: false
```

### Remediate Firewall

Remediate an [Open Firewall](https://cloud.google.com/security-command-center/docs/how-to-remediate-security-health-analytics#open_firewall) rule.

Configuration

- Finding source type: `sha`

- Finding: `open_firewall`

- Action name `remediate_firewall`

Properties:

- `remediation_action`: One of `disable`, `delete` or `update_source_range`.
  - `disable` Will disable the firewall, it means it will not delete the firewall but the firewall rule will not be enforced on the network.
  - `delete` Will delete the fire wall rule.
  - `update_source_range` Will use the `source_ranges` to update the source ranges used in the firewall.
- `source_ranges`: If the `remediation_action` is `update_source_range` the list of IP ranges in [CIDR notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) to replace the current `0.0.0.0/0` range.

```yaml
properties:
  dry_run: false
  remediation_action: update_source_range
  source_ranges:
    - "10.128.0.0/9"
```

### Block SSH Connections

Create a firewall rule to block SSH access from suspicious IPs.

Configuration

- Finding source type: `etd`

- Finding: `ssh_brute_force`

- Action name `remediate_firewall`

Example:

```yaml
properties:
  dry_run: false
```

## Google Kubernetes Engine

### Disable Kubernetes Dashboard addon

Automatically disable the Kubernetes Dashboard addon.

Configuration

- Finding source type: `sha`

- Finding: `web_ui_enabled`

- Action name `disable_dashboard`

Properties:

```yaml
properties:
  dry_run: false
```

## Google Cloud SQL

### Close public Cloud SQL instance

Close a public cloud SQL instance.

Configuration

- Finding source type: `sha`

- Finding: `public_sql_instance`

- Action name `close_cloud_sql`

Properties:

```yaml
properties:
  dry_run: false
```

### Require SSL connection to Cloud SQL

Update Cloud SQL instance to require SSL connections.

Configuration

- Finding source type: `sha`

- Finding: `ssl_not_enforced`

- Action name `cloud_sql_require_ssl`

Properties:

```yaml
properties:
  dry_run: false
```

### Update root password

Update the root password of a Cloud SQL instance.

Configuration

- Finding source type: `sha`

- Finding: `sql_no_root_password`

- Action name `cloud_sql_update_password`

Properties:

```yaml
properties:
  dry_run: false
```

## BigQuery

### Close access to a public BigQuery dataset

Removes public access from a BigQuery dataset.

Configuration

- Finding source type: `sha`

- Finding: `bigquery_public_dataset`

- Action name `close_public_dataset`

Properties:

```yaml
properties:
  dry_run: false
```
