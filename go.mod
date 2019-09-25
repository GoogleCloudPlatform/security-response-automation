module github.com/googlecloudplatform/threat-automation

go 1.11

replace google.golang.org/genproto/googleapis/cloud/securitycenter/v1p1alpha1 => ./private/v1p1alpha1

replace cloud.google.com/go/securitycenter/apiv1p1alpha1 => ./private/apiv1p1alpha1


require (
	cloud.google.com/go v0.45.1
	cloud.google.com/go/pubsub v1.0.1
	cloud.google.com/go/securitycenter/apiv1p1alpha1 v0.0.0-00010101000000-000000000000
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.3.0
	github.com/googleapis/gax-go/v2 v2.0.5
	github.com/kylelemons/godebug v1.1.0
	github.com/pkg/errors v0.8.1
	google.golang.org/api v0.10.0
	google.golang.org/genproto v0.0.0-20190905072037-92dd089d5514
	google.golang.org/genproto/googleapis/cloud/securitycenter/v1p1alpha1 v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.21.1
	gopkg.in/d4l3k/messagediff.v1 v1.2.1
)
