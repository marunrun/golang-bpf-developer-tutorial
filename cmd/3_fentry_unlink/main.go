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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64 fentry_unlink fentry_unlink.c -- -I../../include

func main() {
	var err error
	err = rlimit.RemoveMemlock()
	if err != nil {
		log.Fatal(err)
	}

	var obj fentry_unlinkObjects
	err = loadFentry_unlinkObjects(&obj, &ebpf.CollectionOptions{})
	if err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer obj.Close()

	// 附加 fentry 程序
	fentryLink, err := link.AttachTracing(link.TracingOptions{
		Program: obj.DoUnlinkat,
	})
	if err != nil {
		log.Fatal("create fentry link error ", err)
	}
	defer fentryLink.Close()
	// 附加 unlink 程序
	unlinkLink, err := link.AttachTracing(link.TracingOptions{
		Program: obj.DoUnlinkatExit,
	})
	if err != nil {
		log.Fatal("create unlinkLinkExit link error ", err)
	}
	defer unlinkLink.Close()

	log.Println("Hello World! load")
	log.Println("Program is running. Press Ctrl+C to exit.")
	// 等待信号

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
