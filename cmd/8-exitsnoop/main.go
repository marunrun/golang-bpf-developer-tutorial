package main

import (
	"bpf-developer-tutorial/pkg/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64  -type event exitsnoop exitsnoop.c -- -I../../include

type Event exitsnoopEvent

func main() {

	var err error
	if err = rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
	var obj exitsnoopObjects
	if err = loadExitsnoopObjects(&obj, nil); err != nil {
		panic(err)
	}
	defer obj.Close()

	tracepoint, err := link.Tracepoint("sched", "sched_process_exit", obj.HandleExit, nil)
	if err != nil {
		panic(err)
	}
	defer tracepoint.Close()

	reader, err := ringbuf.NewReader(obj.exitsnoopMaps.Rb)
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	println("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")
	go utils.ShutdownListenWithCallback(func() {
		err2 := reader.Close()
		if err2 != nil {
			panic(err2)
		}
	})

	var event Event
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("ringbuf closed")
				break
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			log.Printf("reading from record: %s", err)
			continue
		}

		log.Printf("pid: %d\tcomm: %s duration: %d\t exitCode:%d\t\n ", event.Pid, event.Comm, event.DurationNs, event.ExitCode)

	}

}
