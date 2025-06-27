package main

import (
	"bpf-developer-tutorial/pkg/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	manager "github.com/gojue/ebpfmanager"
	"github.com/mmat11/usdt"
	"github.com/spf13/cobra"
	"log"
	"os"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64 javagc javagc.c -- -I../../include

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "15-javagc",
	Short: "javagc monitoring tools",
	Long: `javagc monitoring tools - Monitor TCP state changes and RTT

This tool provides two monitoring modes:
- tcpstate: Monitor TCP state changes in the system
- tcprtt: Monitor TCP round-trip time (RTT) statistics`,
	Run: runJavaGc,
}
var (
	targetPid int32
)

func init() {
	rootCmd.Flags().Int32VarP(&targetPid, "target_pid", "p", 0, "目标 进程id")
}
func main() {

	err := rootCmd.Execute()
	if err != nil {
		panic(err)
	}

}

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			Section:          "uprobe/gc__begin",
			EbpfFuncName:     "hogc__begin",
			AttachToFuncName: "readline",
			BinaryPath:       "/usr/bin/bash",
		},
	},
}

func runJavaGc(cmd *cobra.Command, args []string) {

	err := rlimit.RemoveMemlock()
	if err != nil {
		panic(err)
	}
	spec, err := loadJavagc()
	if err != nil {
		panic(err)
	}

	err = spec.Variables["time"].Set(uint32(1))
	if err != nil {
		panic(err)
	}

	var obj javagcObjects
	err = spec.LoadAndAssign(&obj, nil)
	if err != nil {
		panic(err)
	}
	defer obj.Close()

	u, err := usdt.New(obj.HandleGcStart, "hotspot", "gc__begin", int(targetPid))
	if err != nil {
		panic(err)
	}
	defer u.Close()

	e, err := usdt.New(obj.HandleGcEnd, "hotspot", "gc__end", int(targetPid))
	if err != nil {
		panic(err)
	}
	defer e.Close()

	rd, err := perf.NewReader(obj.PerfMap, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer rd.Close()
	go utils.ShutdownListenWithCallback(func() {
		rd.Close()
	})

	var event javagcDataT
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("read from reader: %v", err)
			continue
		}

		// Parse the ringbuf event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parse ringbuf event: %v", err)
			continue
		}

		fmt.Printf("%d:%d->%d \n", event.Pid, event.Cpu, event.Ts)
	}

}
