package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64 kprobe kprobe.c -- -I../../include
func main() {
	var err error
	err = rlimit.RemoveMemlock()
	if err != nil {
		log.Fatal(err)
	}

	var obj kprobeObjects
	err = loadKprobeObjects(&obj, &ebpf.CollectionOptions{})
	if err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer obj.Close()

	tracepoint, err := link.Kprobe("do_unlinkat", obj.DoUnlinkat, &link.KprobeOptions{})
	if err != nil {
		log.Fatal("attach tracepoint error ", err)
	}
	defer tracepoint.Close()

	l, err := link.Kretprobe("do_unlinkat", obj.DoUnlinkatExit, &link.KprobeOptions{})
	if err != nil {
		log.Fatal("attach tracepoint error ", err)
	}
	defer l.Close()

	log.Println("Kprobe is running. Press Ctrl+C to exit.")

	timer := time.Tick(2 * time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-timer:
			log.Println(".")
		case <-stop:
			return
		}

	}

}
