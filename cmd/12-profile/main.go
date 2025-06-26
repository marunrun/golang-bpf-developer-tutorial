package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64 -type stacktrace_event  profile profile.c -- -I../../include

// Constants from profile.c
const (
	MaxStackDepth = 128
	TaskCommLen   = 16
)

// StackEvent represents the event structure used in the eBPF program
type StackEvent struct {
	PID      uint32
	CPUID    uint32
	Comm     [TaskCommLen]byte
	KStackSz int32
	UStackSz int32
	KStack   [MaxStackDepth]uint64
	UStack   [MaxStackDepth]uint64
}

func main() {
	// 移除内存锁限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("移除内存锁限制失败: %v", err)
	}

	// 加载 eBPF 程序
	spec, err := loadProfile()
	if err != nil {
		log.Fatalf("加载 eBPF 程序失败: %v", err)
	}

	var obj profileObjects
	err = spec.LoadAndAssign(&obj, nil)
	if err != nil {
		log.Fatalf("加载 eBPF 对象失败: %v", err)
	}
	defer obj.Close()

	// 设置目标 PID（0 表示所有进程）
	if err := spec.Variables["target_pid"].Set(uint32(0)); err != nil {
		log.Printf("设置目标 PID 失败: %v", err)
	}

	// 附加到性能事件
	perfLink, err := attachToPerfEvent(obj.Profile)
	if err != nil {
		log.Fatalf("附加性能事件失败: %v", err)
	}
	defer perfLink.Close()

	// 创建 ring buffer 读取器
	reader, err := ringbuf.NewReader(obj.profileMaps.Events)
	if err != nil {
		log.Fatalf("创建 ring buffer 读取器失败: %v", err)
	}
	defer reader.Close()

	log.Println("性能分析器已启动，按 Ctrl+C 停止...")

	// 处理信号
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("收到停止信号，正在退出...")
		cancel()
	}()

	// 处理事件
	go handleEvents(ctx, reader)

	// 等待取消信号
	<-ctx.Done()
}

func getCPUCount() int {
	// 简单的 CPU 数量检测
	if count := os.Getenv("NPROC"); count != "" {
		return 4 // 默认值
	}
	return 4 // 默认 4 个 CPU
}

func getOnlineCpus() int {
	return runtime.NumCPU()
}

// attachToPerfEvent 将 eBPF 程序附加到性能事件上
func attachToPerfEvent(prog *ebpf.Program) (link.Link, error) {

	// 使用 tracepoint 附加 eBPF 程序
	// 对于 CPU 性能分析，我们使用 timer 事件
	l, err := link.Tracepoint("timer", "hrtimer_expire_entry", prog, nil)
	if err != nil {
		// 如果 timer 不可用，尝试使用 sched 事件
		l, err = link.Tracepoint("sched", "sched_switch", prog, nil)
		if err != nil {
			return nil, fmt.Errorf("无法附加到任何性能事件: %w", err)
		}
	}

	return l, nil
}

func handleEvents(ctx context.Context, reader *ringbuf.Reader) {
	eventCount := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("读取 ring buffer 失败: %v", err)
			continue
		}

		event, err := parseStackEvent(record.RawSample)
		if err != nil {
			log.Printf("解析事件失败: %v", err)
			continue
		}

		eventCount++
		processStackEvent(event, eventCount)
	}
}

func parseStackEvent(data []byte) (*StackEvent, error) {
	if len(data) < 8 { // 至少需要 PID + CPU_ID
		return nil, fmt.Errorf("数据太短: %d 字节", len(data))
	}

	event := &StackEvent{}

	// 解析固定字段
	event.PID = binary.LittleEndian.Uint32(data[0:4])
	event.CPUID = binary.LittleEndian.Uint32(data[4:8])

	// 复制进程名
	copy(event.Comm[:], data[8:8+TaskCommLen])

	// 解析堆栈大小
	offset := 8 + TaskCommLen
	event.KStackSz = int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
	event.UStackSz = int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))

	// 解析内核堆栈
	offset += 8
	for i := 0; i < MaxStackDepth && offset+8 <= len(data); i++ {
		event.KStack[i] = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	// 解析用户堆栈
	for i := 0; i < MaxStackDepth && offset+8 <= len(data); i++ {
		event.UStack[i] = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	return event, nil
}

func processStackEvent(event *StackEvent, count int) {
	// 获取进程名（去除空字符）
	comm := string(event.Comm[:])
	for i, b := range event.Comm {
		if b == 0 {
			comm = string(event.Comm[:i])
			break
		}
	}

	// 每100个事件打印一次统计
	if count%100 == 0 {
		fmt.Printf("[%s] 已处理 %d 个堆栈跟踪事件\n",
			time.Now().Format("15:04:05"), count)
	}

	// 打印堆栈信息（每50个事件打印详细信息）
	if count%50 == 0 {
		fmt.Printf("\n=== 堆栈跟踪 #%d ===\n", count)
		fmt.Printf("PID: %d, CPU: %d, 进程: %s\n",
			event.PID, event.CPUID, comm)
		fmt.Printf("内核堆栈大小: %d, 用户堆栈大小: %d\n",
			event.KStackSz, event.UStackSz)

		// 打印内核堆栈前几帧
		if event.KStackSz > 0 {
			fmt.Println("内核堆栈帧:")
			frames := event.KStackSz / 8
			if frames > 5 {
				frames = 5 // 只显示前5帧
			}
			for i := 0; i < int(frames); i++ {
				if event.KStack[i] != 0 {
					fmt.Printf("  [%d] 0x%x\n", i, event.KStack[i])
				}
			}
		}

		// 打印用户堆栈前几帧
		if event.UStackSz > 0 {
			fmt.Println("用户堆栈帧:")
			frames := event.UStackSz / 8
			if frames > 5 {
				frames = 5 // 只显示前5帧
			}
			for i := 0; i < int(frames); i++ {
				if event.UStack[i] != 0 {
					fmt.Printf("  [%d] 0x%x\n", i, event.UStack[i])
				}
			}
		}
		fmt.Println()
	}
}
