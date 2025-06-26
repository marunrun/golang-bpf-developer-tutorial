package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strconv"
	"strings"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64 -type event tcpstate tcpstate.c -- -I../../include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target arm64,amd64  tcprtt tcprtt.c -- -I../../include

const (
	AfInet  = 2
	AfInet6 = 10
)

type StateEvent tcpstateEvent

// 用于解析端口列表的自定义类型
type portList []uint16

func (p *portList) String() string {
	if p == nil || len(*p) == 0 {
		return ""
	}
	var ports []string
	for _, port := range *p {
		ports = append(ports, strconv.Itoa(int(port)))
	}
	return strings.Join(ports, ",")
}

func (p *portList) Set(value string) error {
	if value == "" {
		return nil
	}

	portStrings := strings.Split(value, ",")
	for _, portStr := range portStrings {
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil {
			return fmt.Errorf("invalid port number: %s", portStr)
		}
		if port < 0 || port > 65535 {
			return fmt.Errorf("port number out of range (0-65535): %d", port)
		}
		*p = append(*p, uint16(port))
	}
	return nil
}

func (p *portList) Type() string {
	return "portList"
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "14-tcpstate",
	Short: "TCP monitoring tools",
	Long: `TCP monitoring tools - Monitor TCP state changes and RTT

This tool provides two monitoring modes:
- tcpstate: Monitor TCP state changes in the system
- tcprtt: Monitor TCP round-trip time (RTT) statistics`,
}

func init() {
	// Add subcommands to root command
	rootCmd.AddCommand(tcpstateCmd)
	rootCmd.AddCommand(tcprttCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
