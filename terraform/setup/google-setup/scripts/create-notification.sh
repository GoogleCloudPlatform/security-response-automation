#!/usr/bin/env bash

output=$(gcloud alpha scc notifications create $NOTIFICATION_NAME \
	--organization "$ORG_ID" \
	--description "SCC Alerts" \
	--pubsub-topic $PUBSUB_TOPIC \
	--filter "state=\"ACTIVE\"" 2>&1)

if [ $? -ne 0 ]; then
	EXISTS_ERROR='Requested entity already exists'
	if echo $output | grep "$EXISTS_ERROR"; then
		echo "Skipping resource that already exists"
		exit 0
	else
		echo $output
		exit 1
	fi
fi
