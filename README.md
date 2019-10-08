# Security Response Automation

Cloud Functions to take automated actions on threat and vulnerability findings.

## Note

This project is currently under development and is not yet ready for users. Stay tuned!

## Getting Started

This repository contains libraries to perform common actions and a set of Cloud
Functions that use these libraries. For example
`revoke_external_grants_folders.go` shows how you can revoke IAM grants that
match a specific criteria.

### Installing IAM revoker sample

We'll enable a few needed services first then use Terraform for the rest.

```shell
$ gcloud auth application-default login
$ project=[project ID where the Cloud Function will be installed]
$ for service in cloudresourcemanager pubsub cloudfunctions;
    do gcloud services enable $service.googleapis.com --project=$project;
  done
$ terraform init
$ terraform apply
```

TIP: Instead of entering variables every time you can create `terraform.tfvars`
file and input key value pairs there, i.e.
`automation-project="aerial-jigsaw-235219"`.

If at any point you want to revert the changes we've made just run `terraform
destroy .`

### Reinstalling a Cloud Function

Terraform will create or destroy everything by default. To redeploy a single GCF you can do:

```shell
$ zip -r ./deploy/functions.zip . -x *deploy* -x *.git* -x *.terraform*
$ terraform apply .
```

Then visit Cloud Console, Cloud Functions, click the Function name then edit. Finally hit deploy.

### Test

```shell
$ go test ./...
```

## CSCC notifications setup

- Need to grant automation account the proper permissions. Below example shown if adding via the
  config service account. Note the granting account must have organization admin to grant this
  role.
- Make sure to edit `enable-cscc-notifications.sh` and fill in your variables to match your
  environment.

```shell
./enable-cscc-notifications.sh
```
