package main

import (
	"bpf-developer-tutorial/pkg/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS  -target arm64,amd64 -type event execsnoop execsnoop.c -- -I../../include -I.

type Event execsnoopEvent

func main() {
	var err error
	err = rlimit.RemoveMemlock()
	if err != nil {
		panic(err)
	}

	var obj execsnoopObjects
	err = loadExecsnoopObjects(&obj, nil)
	if err != nil {
		panic(err)
	}
	defer obj.Close()
	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_execve", obj.TracepointSyscallsSysEnterExecve, &link.TracepointOptions{})
	if err != nil {
		panic(err)
	}
	defer tracepoint.Close()

	reader, err := perf.NewReader(obj.execsnoopMaps.Events, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			var event Event
			if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing event: %s", err)
				continue
			}

			// 将 C 字符串转换为 Go 字符串
			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

			fmt.Printf("%-8d %-8d %-8d %-16s\n", event.Pid, event.Ppid, event.Uid, comm)
		}
	}()

	utils.ShutdownListen()
}
