#!/usr/bin/env bash

output=$(gcloud alpha scc notifications delete $NOTIFICATION_NAME \
	--organization "$ORG_ID" --quiet 2>&1)

if [ $? -ne 0 ]; then
	DNE_ERROR='Requested entity was not found'
	if echo $output | grep "$DNE_ERROR"; then
		echo "Skipping resource that doesn't exist"
		exit 0
	else
		echo $output
		exit 1
	fi
fi
