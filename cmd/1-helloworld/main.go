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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS  hello hello.c -- -I../headers

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Remove Memlocl err ", err)
	}

	var obj helloObjects

	err := loadHelloObjects(&obj, &ebpf.CollectionOptions{})
	if err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer obj.Close()
	log.Println("Hello World! load")

	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_write", obj.helloPrograms.HandleTp, &link.TracepointOptions{})

	if err != nil {
		log.Fatal("attach tracepoint error ", err)
	}
	defer tracepoint.Close()

	log.Println("Program is running. Press Ctrl+C to exit.")
	log.Println("You can check kernel logs with: sudo dmesg | tail -f")

	tick := time.Tick(2 * time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			log.Println("Hello World! tick")
		case <-stop:
			log.Println("Hello World! stop")
			return
		}
	}
}
