generate:
	go generate ./...

tools:
	go install github.com/securego/gosec/v2/cmd/gosec
	go install github.com/fzipp/gocyclo/cmd/gocyclo
	go install golang.org/x/lint/golint

fmt:
	go fmt ./...

lint: generate fmt
	go vet ./...
	gocyclo -over 20 -ignore ".*_test.go" .
	golint ./...
	gosec -severity medium -quiet ./...

test: lint
	go test ./...
.PHONY: generate fmt test
