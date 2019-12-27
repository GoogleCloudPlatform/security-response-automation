# Troubleshooting Security Response Automation

This guide is for troubleshooting errors that may occur with the Security Response Automation cloud functions

## 1) Error "googleapi: Error 403: The caller does not have permission, forbidden" and "failed to get project ancestry path for project X"

If you see this error it means that the service account `automation-service-account@<automation-project>.gserviceaccount.com` does not have the
*Browser* role and Security Response Automation cannot check if it is allowed to remediate issues on the project based in the project id.

The service account needs the role *Browser* - `roles/browser` on the project or folder that contains the project.
This role is granted to the service account on the folders provided on the terraform variable `folder-ids`.
Seeing this message indicates that the project related to the finding been processed is not under
the folders on the list or that the role has been removed from the service account.

- The Project is not under one of the folder configured folder: You can grant role *Browser* - `roles/browser`
to service account `automation-service-account@<automation-project>.gserviceaccount.com` on the project
or you can move the project under one of the folder.
- The service account `automation-service-account@<automation-project>.gserviceaccount.com` no longer has
the role *Browser* on the folder: You can re-run terraform or add it manually on Google Cloud Console

## 2) Error "googleapi: Error 403: Required '*PERMISSION*' permission for '*RESOURCE*', forbidden" or "googleapi: Error 403: *SERVICE-ACCOUNT* does not have *PERMISSION* access to *RESOURCE*, forbidden"

If you see this error it means that the service account `automation-service-account@<automation-project>.gserviceaccount.com`/*SERVICE-ACCOUNT*
does not have the roles need to perform one of the automations.

Check the beginning of the error message `failed to execute <AUTOMATION> automation with values`
or the field `resource.labels.function_name` in the log entry
to find out which is the automation that is falling.

You can find in `automations.md` which are the required roles for the service account for this automation.
You can follow the same instructions to fix it as listed on the first item
of this guide, that fixes the missing *Browser* role.
