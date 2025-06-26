package main

import (
	"bpf-developer-tutorial/pkg/utils"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64 runqlat runqlat.c -- -I../../include

const (
	MaxSlots    = 27
	TaskCommLen = 16
)

// Hist represents the histogram structure from BPF
// 注意：结构体必须与 C 结构体完全匹配，包括内存对齐
type Hist runqlatHist

// Config holds configuration options
type Config struct {
	Interval     time.Duration
	Count        int
	Milliseconds bool
	PerProcess   bool
	PerThread    bool
	PerPidNs     bool
	TargetTgid   uint32
	FilterCgroup bool
	CgroupPath   string
}

func main() {
	config := Config{
		Interval:     time.Second * 2,
		Milliseconds: true,
		PerProcess:   true,
		PerThread:    true,
		PerPidNs:     true,
		FilterCgroup: true,
		TargetTgid:   506592,
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled eBPF program
	spec, err := loadRunqlat()
	if err != nil {
		log.Fatalf("loading eBPF spec: %v", err)
	}

	// Set constant values before loading
	if err := spec.RewriteConstants(map[string]interface{}{
		"targ_ms":          config.Milliseconds,
		"targ_per_process": config.PerProcess,
		"targ_per_thread":  config.PerThread,
		"targ_per_pidns":   config.PerPidNs,
		"filter_cg":        config.FilterCgroup,
		"targ_tgid":        config.TargetTgid,
	}); err != nil {
		log.Fatalf("rewriting constants: %v", err)
	}

	// Load eBPF program
	objs := runqlatObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach to raw tracepoints
	links := make([]link.Link, 0, 3)
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// Attach sched_wakeup
	wakeupLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_wakeup",
		Program: objs.HandleSchedWakeup,
	})
	if err != nil {
		log.Fatalf("attaching sched_wakeup: %v", err)
	}
	links = append(links, wakeupLink)

	// Attach sched_wakeup_new
	wakeupNewLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_wakeup_new",
		Program: objs.HandleSchedWakeupNew,
	})
	if err != nil {
		log.Fatalf("attaching sched_wakeup_new: %v", err)
	}
	links = append(links, wakeupNewLink)

	// Attach sched_switch
	switchLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_switch",
		Program: objs.HandleSchedSwitch,
	})
	if err != nil {
		log.Fatalf("attaching sched_switch: %v", err)
	}
	links = append(links, switchLink)

	fmt.Println("Tracing run queue latency... Hit Ctrl-C to end.")

	// Setup signal handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalCh
		cancel()
	}()

	// Start monitoring
	monitor(ctx, &objs, config)
}

func monitor(ctx context.Context, objs *runqlatObjects, config Config) {
	ticker := time.NewTicker(config.Interval)
	defer ticker.Stop()

	count := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printHist(objs.Hists, 0)
			count++
			if config.Count > 0 && count >= config.Count {
				return
			}
		}
	}
}
func printHist(m *ebpf.Map, syscallID uint32) {
	fmt.Println("\n=== Histogram Data ===")

	// 遍历 hists map 中的所有条目
	var key uint32
	var hist Hist

	iter := m.Iterate()
	count := 0

	for iter.Next(&key, &hist) {
		count++

		// 计算总数
		sum := uint32(0)
		for _, slot := range hist.Slots {
			sum += slot
		}

		// 如果没有数据则跳过
		if sum == 0 {
			continue
		}

		// 获取进程名称
		commStr := string(hist.Comm[:])
		// 找到字符串结束位置
		if nullIdx := findNull(hist.Comm[:]); nullIdx >= 0 {
			commStr = string(hist.Comm[:nullIdx])
		}

		fmt.Printf("\nProcess: %s (key: %d, total: %d)\n", commStr, key, sum)

		// 打印直方图
		utils.PrintLog2Hist(hist.Slots[:], "usecs")
	}

	if err := iter.Err(); err != nil {
		log.Printf("Error iterating map: %v", err)
		return
	}

	if count == 0 {
		fmt.Println("No data found in histogram map")

		// 调试信息：检查map是否为空
		info, err := m.Info()
		if err != nil {
			log.Printf("Error getting map info: %v", err)
		} else {
			fmt.Printf("Map info - Type: %v, KeySize: %d, ValueSize: %d, MaxEntries: %d\n",
				info.Type, info.KeySize, info.ValueSize, info.MaxEntries)
		}
	} else {
		fmt.Printf("\nProcessed %d entries from histogram map\n", count)
	}
}

// 辅助函数：查找字节数组中的null终止符
func findNull(b []byte) int {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return -1
}

// 添加调试函数来检查结构体大小
func init() {
	log.Printf("Hist struct size: %d bytes", unsafe.Sizeof(Hist{}))
	log.Printf("Expected size: %d bytes", TaskCommLen+MaxSlots*4)
}
