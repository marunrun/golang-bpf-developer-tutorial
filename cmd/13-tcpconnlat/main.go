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
	"golang.org/x/sys/unix"
	"net"
	"os"
	"unsafe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64 -type event tcpconnlat tcpconnlat.c -- -I../../include

type TcpEvent tcpconnlatEvent

func main() {
	err := rlimit.RemoveMemlock()
	if err != nil {
		panic(err)
	}

	spec, err := loadTcpconnlat()
	if err != nil {
		panic(err)
	}

	// 设置目标
	//spec.Variables["target_pid"].Set(int32(1))
	//spec.Variables["min_duration_ns"].Set(time.Millisecond)
	var obj tcpconnlatObjects
	err = spec.LoadAndAssign(&obj, nil)
	if err != nil {
		panic(err)
	}
	defer obj.Close()
	kprobe, err := link.Kprobe("tcp_v4_connect", obj.TcpV4Connect, nil)
	if err != nil {
		panic(err)
	}
	defer kprobe.Close()

	v6, err := link.Kprobe("tcp_v6_connect", obj.TcpV6Connect, nil)
	if err != nil {
		panic(err)
	}
	defer v6.Close()

	process, err := link.Kprobe("tcp_rcv_state_process", obj.TcpRcvStateProcess, nil)
	if err != nil {
		panic(err)
	}
	defer process.Close()

	reader, err := perf.NewReader(obj.Events, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	go utils.ShutdownListenWithCallback(func() {
		_ = reader.Close()
	})

	var event TcpEvent
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				println("perf reader closed, exiting..")
				return
			}
			fmt.Printf("reading from reader: %s", err)
			continue
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			fmt.Printf("parsing event: %s", err)
			continue
		}
		processEvent(&event)
	}

}

func processEvent(event *TcpEvent) {
	comm := event.GetComm()
	saddr := event.FormatSaddr()
	daddr := event.FormatDaddr()

	fmt.Printf("%-16s %s:%-5d -> %s:%-5d latency:%8dus ts:%-12d\n",
		comm,
		saddr, event.Lport,
		daddr, event.Dport,
		event.DeltaUs,
		event.TsUs)
}

// FormatSaddr 格式化源地址
func (e *TcpEvent) FormatSaddr() string {
	switch e.Af {
	case 2: // AF_INET (IPv4)
		return formatIPv4(e.GetSaddrV4())
	case 10: // AF_INET6 (IPv6)
		return formatIPv6(e.GetSaddrV6())
	default:
		return "unknown"
	}
}

// GetSaddrV4 获取源地址 IPv4
func (e *TcpEvent) GetSaddrV4() uint32 {
	return e.SaddrV4
}

// GetSaddrV6 获取源地址 IPv6
func (e *TcpEvent) GetSaddrV6() [16]byte {
	var ipv6 [16]byte
	// 使用 unsafe 访问 union 的 IPv6 部分
	ptr := unsafe.Pointer(&e.SaddrV4)
	copy(ipv6[:], (*[16]byte)(ptr)[:])
	return ipv6
}

// GetDaddrV4 获取目标地址 IPv4
func (e *TcpEvent) GetDaddrV4() uint32 {
	return e.DaddrV4
}

// GetDaddrV6 获取目标地址 IPv6
func (e *TcpEvent) GetDaddrV6() [16]byte {
	var ipv6 [16]byte
	// 使用 unsafe 访问 union 的 IPv6 部分
	ptr := unsafe.Pointer(&e.DaddrV4)
	copy(ipv6[:], (*[16]byte)(ptr)[:])
	return ipv6
}

// FormatDaddr 格式化目标地址
func (e *TcpEvent) FormatDaddr() string {
	switch e.Af {
	case 2: // AF_INET (IPv4)
		return formatIPv4(e.GetDaddrV4())
	case 10: // AF_INET6 (IPv6)
		return formatIPv6(e.GetDaddrV6())
	default:
		return "unknown"
	}
}

// 格式化 IPv4 地址
func formatIPv4(addr uint32) string {
	// 注意字节序转换
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip.String()
}

// 格式化 IPv6 地址
func formatIPv6(addr [16]byte) string {
	return net.IP(addr[:]).String()
}

// GetComm 获取进程名
func (e *TcpEvent) GetComm() string {
	return unix.ByteSliceToString(e.Comm[:])
}
