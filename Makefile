.PHONY: all
all: appknox

.PHONY: build
build: appknox

.PHONY: appknox
appknox: bin/appknox-Darwin-x86_64 bin/appknox-Linux-x86_64 bin/appknox-Windows-x86_64.exe

VERSION := $(shell git describe --tags)
BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := $(shell basename "$(PWD)")
SOURCES = $(shell find . -maxdepth 3 -name '*.go' '!' -name '*_test.go')
LDFLAGS := -s -w -X main.version=${VERSION} -X main.commit=${BUILD}

bin/appknox-%-x86_64: $(SOURCES)
	GOOS=$(shell echo $* | tr A-Z a-z) GOARCH=amd64 go build -o $@ -ldflags="$(LDFLAGS)"

bin/appknox-Windows-x86_64.exe: bin/appknox-Windows-x86_64
	cp bin/appknox-Windows-x86_64 $@

.PHONY: clean
clean:
	rm -rf bin/*

.PHONY: test
test:
	go test -v ./...

.PHONY: test_coverage
test_coverage:
	go test -race -coverprofile=coverage.txt -covermode=atomic -v ./...
