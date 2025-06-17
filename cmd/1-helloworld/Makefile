CLANG ?= clang
CFLAGS := -O2 -g -Wall

build: generate
	go build -o ../../bin/hello .

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...
