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

- Configured in settings.json under the `remove_public_ip` key.
- See general [resource list](/README.md#resources) options.

#### Remediate open firewall

Remediate an [Open Firewall](https://cloud.google.com/security-command-center/docs/how-to-remediate-security-health-analytics#open_firewall) rule.

Configuration

- Configured in settings.json under the `open_firewall` key.
- See general [resource list](/README.md#resources) options.
- `remediation_action`: one of `DISABLE`, `DELETE` or `UPDATE_RANGE`
  - `source_ranges`: if the `remediation_action` is `UPDATE_RANGE` the list of IP ranges in [CIDR notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) to replace the current `0.0.0.0/0` range.

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

- Configured in settings.json under the `close_cloud_sql` key.
- See general [resource list](/README.md#resources) options.

#### Require SSL connection to Cloud SQL

Update Cloud SQL instance to require SSL connections.

Configuration

- Configured in settings.json under the `cloud_sql_require_ssl` key.
- See general [resource list](/README.md#resources) options.

### BigQuery

#### Close access to a public BigQuery dataset

Removes public access from a BigQuery dataset.

Configuration

- Configured in settings.json under the `close_public_dataset` key.
- See general [resource list](/README.md#resources) options.
