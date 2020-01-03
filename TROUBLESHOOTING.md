# Troubleshooting Security Response Automation

This guide is for troubleshooting errors that may occur during execution of Security Response Automation.

## 1) "Error 403"

Error 403 messages refer to the service account `automation-service-account@<automation-project>.iam.gserviceaccount.com`.
The required roles can be found in the terraform module for each one of the automations.
You will need to grant the required roles to the service account on the project or ancestor of the project for the automation to work.

## 2) "got rule "X" with 0 automations"

This log entry means that a known finding of rule *X* was received but no automation was configured for it in `cloudfunctions/router/config.yaml`.
This may be the expected result if no automation was configured for it. If an automation was configured, please check the config.yaml file.
You will need to run `terraform apply` again to update the `router` cloud function if you make any changes to the config.yaml file.

Known rules are listed in `cloudfunctions/router/empty-config.yaml` under `etd` and `sha` sections.

## 3)  "rule "X" not found"

This log entry means that an unknown finding of rule *X* was received.
If X is not empty, "X" is the category in Security Command Center findings or
the rule name from the detection category in Event Thread Detection findings.
If X is empty it means that it was not possible to unmarshal the message received by the `router` cloud function.
