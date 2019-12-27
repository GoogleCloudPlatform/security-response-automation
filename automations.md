# Automation Modules

These are the available Cloud Functions modules:

- router
- close_public_bucket
- enable_bucket_only_policy
- revoke_iam_grants
- create_disk_snapshot
- open_firewall
- remove_public_ip
- close_public_dataset
- close_public_cloud_sql
- cloud-sql-require-ssl
- disable_dashboard
- update_password
- enable_audit_logs

## Google Cloud Storage

### Remove public access

Removes public access from Google Cloud Storage buckets.

Configuration

- Action name `close_bucket`

Example:

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
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
```

### Enable bucket only policy

Enable [Bucket Policy Only](https://cloud.google.com/storage/docs/bucket-policy-only) in Google Cloud Storage buckets.

Configuration

- Action name `enable_bucket_only_policy`

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      bucket_policy_only_disabled:
        - action: enable_bucket_only_policy
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
```

## IAM

### Revoke IAM grants

Removes members from an IAM policy.

Configuration

- Action name `iam_revoke`

Before a user is removed the user is checked against the below lists. These lists are meant to be mutually exclusive however this is not enforced. These lists allow you to specify exactly what domain names are disallowed or conversely which domains are allowed.

- `allow_domains` An array of strings containing domain names to be matched. If the member added matches a domain in this list do not remove it. At least one domain is required in this list.

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      anomalous_iam:
        - action: iam_revoke
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
            allow_domains:
              - google.com
```

### Remove non-Organization members

Removes non-organization members from resource level IAM policy.

Configuration

- Action name `remove_non_org_members`

Before a user is removed, the user is checked against the below lists. These lists are meant to be mutually exclusive however this is not enforced. These lists allow you to specify exactly what domain names are disallowed or conversely which domains are allowed.

- `allow_domains` An array of strings containing domain names to be matched. If the member added matches a domain in this list do not remove it. At least one domain is required in this list.

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      non_org_members:
        - action: remove_non_org_members
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
            allow_domains: ["prod.foo.com", "google.com", "foo.com"]
```

## Google Compute Engine

### Create Snapshot

Automatically create a snapshot of all disks associated with a GCE instance.

Configuration

- action `gce_create_disk_snapshot`
- `target_snapshot_project_id` Project ID where disk snapshots should be sent to. If outputting to Turbinia this should be the same as `turbinia_project_id`.
- `target_snapshot_project_zone` Zone where disk snapshots should be sent to. If outputting to Turbinia this should be the same as `turbinia_zone`.
- `output` Repeated set of optional output destinations after the function has executed.
  - `turbinia` Will notify Turbinia when a snapshot is created.

Required if output contains `turbinia`:

The below keys are placed under the `turbinia` key:

- `project_id` Project ID where Tubinia is installed.
- `topic_name` Pub/Sub topic where we should notify Turbinia.
- `zone` Zone where Turbinia disks are kept.

Example:

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
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
            target_snapshot_project_id: target-projectid
            target_snapshot_zone: us-central1
            output:
            turbinia:
              project_id: turbinia-project
              topic: turbinia-topic
              zone: us-central1-a
```

### Remove public IPs from an instance

Removes all public IPs from an instance's network interface.

Configuration

- Action name `remove_public_ip`

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      public_ip_address:
        - action: remove_public_ip
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
            unknow: ["a","b"]
```

### Remediate Firewall

Remediate an [Open Firewall](https://cloud.google.com/security-command-center/docs/how-to-remediate-security-health-analytics#open_firewall) rule.

Configuration

- Action name `remediate_firewall`
- `remediation_action`: One of `disable`, `delete` or `update_source_range`.
  - `disable` Will disable the firewall, it means it will not delete the firewall but the firewall rule will not be enforced on the network.
  - `delete` Will delete the fire wall rule.
  - `update_source_range` Will use the `source_ranges` to update the source ranges used in the firewall.
- `source_ranges`: If the `remediation_action` is `update_source_range` the list of IP ranges in [CIDR notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) to replace the current `0.0.0.0/0` range.

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      open_firewall:
        - action: remediate_firewall
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
            # values for remediation_action: disable, delete, update_source_range
            remediation_action: update_source_range
            source_ranges:
              - "10.128.0.0/9"
```

### Block SSH Connections

Create a firewall rule to block SSH access from suspicious IPs.

Configuration

- Action name `remediate_firewall`

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    etd:
      ssh_brute_force:
        - action: remediate_firewall
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
```

## Google Kubernetes Engine

### Disable Kubernetes Dashboard addon

Automatically disable the Kubernetes Dashboard addon.

Configuration

- Action name `disable_dashboard`

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      web_ui_enabled:
        - action: disable_dashboard
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
```

## Google Cloud SQL

### Close public Cloud SQL instance

Close a public cloud SQL instance.

Configuration

- Action name `close_cloud_sql`

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      public_sql_instance:
        - action: close_cloud_sql
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
```

### Require SSL connection to Cloud SQL

Update Cloud SQL instance to require SSL connections.

Configuration

- Action name `cloud_sql_require_ssl`

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      ssl_not_enforced:
        - action: cloud_sql_require_ssl
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
```

### Update root password

Update the root password of a Cloud SQL instance.

Configuration

- Action name `cloud_sql_update_password`

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      sql_no_root_password:
        - action: cloud_sql_update_password
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
```

## BigQuery

### Close access to a public BigQuery dataset

Removes public access from a BigQuery dataset.

Configuration

- Action name `close_public_dataset`

Example:

```yaml
apiVersion: security-response-automation.cloud.google.com/v1alpha1
kind: Remediation
metadata:
  name: router
spec:
  parameters:
    sha:
      bigquery_public_dataset:
        - action: close_public_dataset
          target:
            - organizations/0000000000000/folders/000000000000/*
          exclude:
            - organizations/1111111111111/folders/111111111111/*
          properties:
            dry_run: false
```
