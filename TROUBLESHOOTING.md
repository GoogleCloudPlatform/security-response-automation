# Troubleshooting Security Response Automation

This guide is for troubleshooting errors that may occur with the Security Response Automation cloud functions.

## 1) Error 403

Error 403 messages refer to the service account `automation-service-account@<automation-project>.gserviceaccount.com`.
In this case the service account is missing one of the required roles for the automation executed.

- `"failed to get project ancestry path for project X"`: this message occurs in the `router` cloud function. It means that the service account
is missing role *Browser* - `roles/browser` on the project or folder that contains the project.
- `"failed to publish to "threat-findings..." ... rpc error: code = PermissionDenied desc = User not authorized to perform this action."`:
this message also occurs in the `router` cloud function. It means that the service account is missing role *Pub/Sub Editor* - `roles/pubsub.editor`
on the automation project.
- `"failed to execute <AUTOMATION> automation with values"`: in the other cases, the start of the error message will hint on the `AUTOMATION` that failed.
You can also look at the field `resource.labels.function_name` in the log entry to find out which automation failed.

You can find in [automations](/automations.md) which are the required roles for the service account for this automation.
You will need to grant the required roles to the service for the automation to work.
The error message will also contain the project in which the service account needs the permission, like `... ProjectID:decent-ellipse-00000 ...`
or `... on project "decent-ellipse-00000" ...`

If the project is under one of the folders provided on the terraform variable `folder-ids`,
the service account should have the right role, granted by the terraform script on deploy.
Re-run terraform(*recommended*) or add the roles manually on Google Cloud Console to fix this error.

If the project is *not* under one of the folders provided on the terraform variable `folder-ids`,
you can grant role the required role to service account `automation-service-account@<automation-project>.gserviceaccount.com`
on the project or you can move the project under one of the folders.

## 2) "got rule "X" with 0 automations"

This log entry means that a known finding of rule *X* was received but no automation was configured for it in the file `cloudfunctions/router/config.yaml`.

This may be the expected result if no automation was configured for it.
If an automation was configured please check the config file to validate its format and if the automation names are correct.
