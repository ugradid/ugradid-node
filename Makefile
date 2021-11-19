PROJECT_NAME=ugradid-node
MAIN_FILE=main.go

install-tools:
	go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.8.2
	go install github.com/golang/mock/mockgen@v1.6.0
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26.0
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0

gen-protobuf: # Init Service
	protoc --go_out=paths=source_relative:network -I network network/transport/v1/protobuf/network.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/v1/protobuf/network.proto

gen-api:
	oapi-codegen -generate types,server,client -templates codegen/oapi/ -package v1 docs/static/network/v1.yaml | gofmt > network/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v1 -exclude-schemas DIDDocument,DIDDocumentMetadata,Service,VerificationMethod docs/static/vdr/v1.yaml | gofmt > vdr/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v1 -exclude-schemas VerifiableCredential,CredentialSubject,IssueVCRequest,Revocation docs/static/vcr/v1.yaml | gofmt > vcr/api/v1/generated.go

run: # Run develop server
	@go run $(MAIN_FILE) server --configfile etc/ugradid.yml