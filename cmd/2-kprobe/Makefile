CLANG ?= clang
CFLAGS := -O2 -g -Wall

build: generate
	go build -o ../../bin/kprobe .

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

.PHONY:clean
clean:
	rm *_bpfeb*.* *_bpfel*.*