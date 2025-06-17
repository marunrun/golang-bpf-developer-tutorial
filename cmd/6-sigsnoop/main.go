package main

import (
	"bpf-developer-tutorial/pkg/utils"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS  -target arm64,amd64 sigsnoop sigsnoop.c -- -I../../include

func main() {
	var err error
	if err = rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
	var obj sigsnoopObjects
	if err = loadSigsnoopObjects(&obj, nil); err != nil {
		panic(err)
	}
	defer obj.Close()

	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_kill", obj.KillEntry, &link.TracepointOptions{})
	if err != nil {
		panic(err)
	}
	defer tracepoint.Close()

	l, err := link.Tracepoint("syscalls", "sys_exit_kill", obj.KillExit, &link.TracepointOptions{})
	if err != nil {
		panic(err)
	}
	defer l.Close()

	println("Program is running. Press Ctrl+C to exit.")
	println("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")
	utils.ShutdownListen()

}
