package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"os"
	"os/signal"
	"strconv"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS  opensnoop opensnoop.c -- -I../../include

func main() {

	args := os.Args
	if len(args) < 2 {
		println("Usage: ./opensnoop <target pid>")
		os.Exit(1)
	}
	// 解析 target_pid
	targetPid, err := strconv.Atoi(args[1])
	if err != nil {
		println("Invalid PID:", args[1])
		os.Exit(1)
	}

	opensnoop, err := loadOpensnoop()
	if err != nil {
		panic(err)
	}

	if err = opensnoop.Variables["pid_target"].Set(int32(targetPid)); err != nil {
		panic(err)
	}

	var obj opensnoopObjects
	err = opensnoop.LoadAndAssign(&obj, &ebpf.CollectionOptions{})
	if err != nil {
		panic(err)
	}
	defer obj.Close()

	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_openat", obj.TracepointSyscallsSysEnterOpenat, &link.TracepointOptions{})
	if err != nil {
		panic(err)
	}
	defer tracepoint.Close()
	println("Program is running. Press Ctrl+C to exit.")
	println("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")

	timer := time.Tick(2 * time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-timer:
		case <-stop:
			return
		}

	}
}
