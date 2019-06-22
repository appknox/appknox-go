all: appknox
appknox: bin/appknox-Darwin-x86_64 bin/appknox-Linux-x86_64 bin/appknox-Windows-x86_64

VERSION := $(shell git describe --tags)
BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := $(shell basename "$(PWD)")
SOURCES = $(shell find . -maxdepth 3 -name '*.go' '!' -name '*_test.go')
LDFLAGS := -X main.version=${VERSION} -X main.commit=${BUILD}

bin/appknox-Darwin-x86_64: $(SOURCES)
	GOOS=darwin GOARCH=amd64 go build -o bin/appknox-Darwin-x86_64 -ldflags="$(LDFLAGS)"

bin/appknox-Linux-x86_64: $(SOURCES)
	GOOS=linux GOARCH=amd64 go build -o bin/appknox-Linux-x86_64 -ldflags="$(LDFLAGS)"

bin/appknox-Windows-x86_64: $(SOURCES)
	GOOS=windows GOARCH=amd64 go build -o bin/appknox-Windows-x86_64 -ldflags="$(LDFLAGS)"

clean:
	rm -rf bin/*
