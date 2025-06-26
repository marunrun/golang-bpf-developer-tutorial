package main

import (
	"bpf-developer-tutorial/pkg/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64 -type event tcpstate tcpstate.c -- -I../../include

const (
	AfInet  = 2
	AfInet6 = 10
)

type StateEvent tcpstateEvent

func main() {

	err := rlimit.RemoveMemlock()
	if err != nil {
		panic(err)
	}

	spec, err := loadTcpstate()
	if err != nil {
		panic(err)
	}

	// 设置需要过滤的协议族
	err = spec.Variables["target_family"].Set(uint16(AfInet)) // 过滤 ipv4
	//err = spec.Variables["target_family"].Set(uint16(AfInet6)) // 过滤 ipv6
	if err != nil {
		panic(err)
	}
	err = spec.Variables["filter_by_sport"].Set(false) // 过滤 源端口
	if err != nil {
		panic(err)
	}
	err = spec.Variables["filter_by_dport"].Set(true) // 过滤 目标端口
	if err != nil {
		panic(err)
	}
	var obj tcpstateObjects
	err = spec.LoadAndAssign(&obj, nil)
	if err != nil {
		panic(err)
	}
	defer obj.Close()

	// 设置需要过滤的源端口
	err = setFilterPorts(obj.Sports, []uint16{})
	if err != nil {
		panic(err)
	}

	// 设置需要过滤的目标端口
	err = setFilterPorts(obj.Dports, []uint16{3306})
	if err != nil {
		panic(err)
	}

	tracepoint, err := link.Tracepoint("sock", "inet_sock_set_state", obj.HandleSetState, &link.TracepointOptions{})
	if err != nil {
		panic(err)
	}
	defer tracepoint.Close()

	reader, err := perf.NewReader(obj.Events, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	go utils.ShutdownListenWithCallback(func() {
		reader.Close()
	})

	fmt.Printf("%-16s %-8s %-16s %-16s %-8s %-10s %-10s %-12s -> %-12s %8s\n",
		"SKADDR", "C-PID", "C-COMM", "LADDR", "LPORT", "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS")

	var event StateEvent
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				fmt.Printf("perf reader closed, exiting..")
				return
			}
			fmt.Printf("读取 perf 事件失败: %v", err)
			continue
		}

		err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			fmt.Printf("解析事件失败: %v", err)
			continue
		}

		processEvent(&event)

	}

}

func processEvent(event *StateEvent) {
	// 获取进程名
	comm := unix.ByteSliceToString(event.Task[:])

	// 格式化地址

	// 格式化状态名称
	oldState := getTcpStateName(event.Oldstate)
	newState := getTcpStateName(event.Newstate)

	// 打印事件信息
	fmt.Printf("%-16x %-8d %-16s %-15s %-8d %-15s %-8d %-12s -> %-12s %8d\n",
		event.Skaddr,
		event.Pid,
		comm,
		formatAddress(event.Saddr[:], event.Family),
		event.Sport,
		formatAddress(event.Daddr[:], event.Family),
		event.Dport,
		oldState,
		newState,
		event.DeltaUs/1000) // 转换为毫秒
}

// 根据地址族格式化 IP 地址
func formatAddress(addrBytes []byte, family uint16) string {
	switch family {
	case AfInet: // IPv4
		if len(addrBytes) >= 4 {
			// IPv4 地址通常存储在前 4 个字节
			addr := binary.LittleEndian.Uint32(addrBytes[:4])
			return formatIPv4(addr)
		}
		return "0.0.0.0"
	case AfInet6: // IPv6
		if len(addrBytes) >= 16 {
			return net.IP(addrBytes[:16]).String()
		}
		return "::"
	default:
		return "unknown"
	}
}

// 格式化 IPv4 地址
func formatIPv4(addr uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip.String()
}

func setFilterPorts(m *ebpf.Map, ports []uint16) error {
	for _, port := range ports {
		err := m.Put(port, uint16(1))
		if err != nil {
			return err
		}
	}
	return nil
}
