export PATH := $(GOPATH)/bin:$(PATH)
export GO15VENDOREXPERIMENT := 1

all: fmt build

build: frps frpc

# compile assets into binary file
file:
	rm -rf ./assets/static/*
	cp -rf ./web/frps/dist/* ./assets/static
	go get -d github.com/rakyll/statik
	go install github.com/rakyll/statik
	rm -rf ./assets/statik
	go generate ./assets/...

fmt:
	go fmt ./assets/...
	go fmt ./client/...
	go fmt ./cmd/...
	go fmt ./models/...
	go fmt ./server/...
	go fmt ./utils/...
	
frps:
	go build -o bin/op4mServer ./cmd/frps
	@cp -rf ./assets/static ./bin

frpc:
	go build -o bin/op4mClient ./cmd/frpc

test: gotest

gotest:
	go test -v ./assets/...
	go test -v ./client/...
	go test -v ./cmd/...
	go test -v ./models/...
	go test -v ./server/...
	go test -v ./utils/...

alltest: gotest
	cd ./tests && ./run_test.sh && cd -
	go test -v ./tests/...
	cd ./tests && ./clean_test.sh && cd -

clean:
	rm -f ./bin/op4mServer
	rm -f ./bin/op4mClient
	cd ./tests && ./clean_test.sh && cd -

save:
	godep save ./...
