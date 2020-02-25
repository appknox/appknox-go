all: appknox
build: appknox
appknox: bin/appknox-Darwin-x86_64 bin/appknox-Linux-x86_64 bin/appknox-Windows-x86_64.exe

VERSION := $(shell git describe --tags)
BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := $(shell basename "$(PWD)")
SOURCES = $(shell find . -maxdepth 3 -name '*.go' '!' -name '*_test.go')
LDFLAGS := -X main.version=${VERSION} -X main.commit=${BUILD} -s -w

bin/appknox-Darwin-x86_64: $(SOURCES)
	GO111MODULE=on GOOS=darwin GOARCH=amd64 go build -o bin/appknox-Darwin-x86_64 -ldflags="$(LDFLAGS)"

bin/appknox-Linux-x86_64: $(SOURCES)
	GO111MODULE=on GOOS=linux GOARCH=amd64 go build -o bin/appknox-Linux-x86_64 -ldflags="$(LDFLAGS)"

bin/appknox-Windows-x86_64.exe: $(SOURCES)
	GO111MODULE=on GOOS=windows GOARCH=amd64 go build -o bin/appknox-Windows-x86_64.exe -ldflags="$(LDFLAGS)"

clean:
	rm -rf bin/*

test:
	GO111MODULE=on go test -v ./...

test_coverage:
	GO111MODULE=on go test -race -coverprofile=coverage.txt -covermode=atomic -v ./...

.PHONY: clean test all build appknox test_coverage
