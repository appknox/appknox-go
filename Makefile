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

# The deterministic gate. `make check` is the single command that has to pass
# before anything is committed, so that "did I remember to run vet?" stops
# being a question anyone -- human or agent -- answers from memory.
#
# Format is checked only on files changed against BASE, not the whole tree.
# Files were already unformatted before this target existed; failing on those
# would make the gate useless on its first run, and reformatting them here
# would bury unrelated churn in every diff. `make fmt-all` cleans them up as a
# deliberate, separate change.
BASE ?= origin/develop
CHANGED_GO = $(shell git diff --name-only $(BASE)...HEAD -- '*.go' 2>/dev/null; git diff --name-only -- '*.go'; git ls-files --others --exclude-standard -- '*.go')

.PHONY: check
check: fmt-check vet build-check test

.PHONY: fmt-check
fmt-check:
	@files="$(sort $(CHANGED_GO))"; \
	existing=""; for f in $$files; do [ -f "$$f" ] && existing="$$existing $$f"; done; \
	if [ -z "$$existing" ]; then echo "fmt-check: no changed Go files"; exit 0; fi; \
	bad=$$(gofmt -l $$existing); \
	if [ -n "$$bad" ]; then echo "gofmt needed:"; echo "$$bad"; echo "run: make fmt"; exit 1; fi; \
	echo "fmt-check: ok"

.PHONY: fmt
fmt:
	@files="$(sort $(CHANGED_GO))"; \
	existing=""; for f in $$files; do [ -f "$$f" ] && existing="$$existing $$f"; done; \
	if [ -n "$$existing" ]; then gofmt -w $$existing; echo "formatted:$$existing"; else echo "fmt: nothing to do"; fi

.PHONY: fmt-all
fmt-all:
	gofmt -w .

.PHONY: vet
vet:
	go vet ./...

.PHONY: build-check
build-check:
	go build ./...

.PHONY: test_coverage
test_coverage:
	go test -race -coverprofile=coverage.txt -covermode=atomic -v ./...
