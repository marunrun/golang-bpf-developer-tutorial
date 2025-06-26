package main

import (
	"bpf-developer-tutorial/pkg/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64 -type event ringbuffer ringbuffer.c -- -I../../include

type event ringbufferEvent

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	ringbuffer, err := loadRingbuffer()
	if err != nil {
		panic(err)
	}

	// 设置最小退出为 1 0 秒
	ringbuffer.Variables["min_duration_ns"].Set(time.Millisecond)

	var obj ringbufferObjects
	err = ringbuffer.LoadAndAssign(&obj, nil)
	if err != nil {
		panic(err)
	}
	defer obj.Close()
	tracepoint, err := link.Tracepoint("sched", "sched_process_exit", obj.HandleExit, nil)
	if err != nil {
		panic(err)
	}
	defer tracepoint.Close()

	l, err := link.Tracepoint("sched", "sched_process_exec", obj.HandleExec, nil)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	reader, err := ringbuf.NewReader(obj.ringbufferMaps.Rb)
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	println("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")

	go utils.ShutdownListenWithCallback(func() {
		reader.Close()
	})

	var e event
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				println("ringbuf closed, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e)
		if err != nil {
			log.Printf("parsing event: %s", err)
			continue
		}

		// println
		fmt.Printf("pid:%-8d ppid:%-8d exit_code:%-8d  comm:%-16s isExit:%v  filename:%s duration:%d\n", e.Pid, e.Ppid, e.ExitCode, e.Comm[:], e.ExitEvent, e.Filename[:], e.DurationNs/1000)
	}

}
