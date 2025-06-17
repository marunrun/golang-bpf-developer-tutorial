package main

import (
	"bpf-developer-tutorial/pkg/utils"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS  -target arm64,amd64 uprobe uprobe.c -- -I../../include

func main() {
	var err error
	if err = rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	var obj uprobeObjects

	if err = loadUprobeObjects(&obj, nil); err != nil {
		panic(err)
	}
	defer obj.Close()

	executable, err := link.OpenExecutable("/bin/bash")
	if err != nil {
		panic(err)
	}
	uretprobe, err := executable.Uretprobe("readline", obj.Printret, nil)
	if err != nil {
		panic(err)
	}
	defer uretprobe.Close()

	println("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")
	utils.ShutdownListen()
}
