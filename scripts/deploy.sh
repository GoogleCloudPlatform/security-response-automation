set -e
rm ./deploy/functions.zip &2> /dev/null
zip -r ./deploy/functions.zip . -x *deploy* -x *.git* -x *.terraform*
terraform apply --auto-approve --target module.$1 .
echo "Deploying Cloud Function..."
gcloud functions deploy $2 --project $3
