set -e
zip -r ./deploy/functions.zip . -x *deploy* -x *.git* -x *.terraform*
echo terraform apply --auto-approve . --target module.$1
gcloud functions deploy $2 --project $3