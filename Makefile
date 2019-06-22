all: appknox
appknox: bin/appknox-windows-amd64 bin/appknox-linux-amd64 bin/appknox-darwin-amd64

VERSION := $(shell git describe --tags)
BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := $(shell basename "$(PWD)")
SOURCES = $(shell find . -maxdepth 3 -name '*.go' '!' -name '*_test.go')
LDFLAGS := -X main.version=${VERSION} -X main.commit=${BUILD}

bin/appknox-darwin-amd64: $(SOURCES)
	GOOS=darwin GOARCH=amd64 go build -o bin/appknox-darwin-amd64 -ldflags="$(LDFLAGS)"

bin/appknox-linux-amd64: $(SOURCES)
	GOOS=linux GOARCH=amd64 go build -o bin/appknox-linux-amd64 -ldflags="$(LDFLAGS)"

bin/appknox-windows-amd64: $(SOURCES)
	GOOS=windows GOARCH=amd64 go build -o bin/appknox-windows-amd64 -ldflags="$(LDFLAGS)"

clean:
	rm -rf bin/*


