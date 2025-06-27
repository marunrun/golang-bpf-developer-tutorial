package main

import (
	"bpf-developer-tutorial/pkg/utils"
	"context"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"net"
	"os"
	"time"
)

func runTcprtt(cmd *cobra.Command, args []string) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		panic(err)
	}

	spec, err := loadTcprtt()
	if err != nil {
		panic(err)
	}

	applyConfig(spec)

	var obj tcprttObjects
	err = spec.LoadAndAssign(&obj, nil)
	if err != nil {
		panic(err)
	}
	defer obj.Close()

	tracing, err := link.AttachTracing(link.TracingOptions{
		Program: obj.tcprttPrograms.TcpRcv,
	})
	if err != nil {
		fmt.Printf("can't attach fentry tracing: %v. trying to Krpobe tracing\n", err)

		// Attach to tcp_rcv_established using kprobe
		kprobe, err := link.Kprobe("tcp_rcv_established", obj.TcpRcvEstablished, nil)
		if err != nil {
			panic(err)
		}
		defer kprobe.Close()
	} else {
		defer tracing.Close()
	}

	// Display current filter settings
	fmt.Println("TCP RTT monitoring started...")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Local address histogram: %v\n", targLaddrHist)
	fmt.Printf("  Remote address histogram: %v\n", targRaddrHist)
	fmt.Printf("  Show extension summary: %v\n", targShowExt)
	if targSport != 0 {
		fmt.Printf("  Source port filter: %d\n", targSport)
	}
	if targDport != 0 {
		fmt.Printf("  Destination port filter: %d\n", targDport)
	}
	if targSaddr != "" {
		fmt.Printf("  Source address filter: %s\n", targSaddr)
	}
	if targDaddr != "" {
		fmt.Printf("  Destination address filter: %s\n", targDaddr)
	}
	fmt.Printf("  Time unit: %s\n", func() string {
		if targMs {
			return "milliseconds"
		}
		return "microseconds"
	}())
	fmt.Println()

	ctx := utils.ShutdownListenWithContext(context.Background())

	// Print histogram every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nReceived signal, printing final histogram...")
			printHistogram(&obj)
			return
		case <-ticker.C:
			printHistogram(&obj)
		}
	}
}

func applyConfig(spec *ebpf.CollectionSpec) {
	// Set configuration variables
	err := spec.Variables["targ_laddr_hist"].Set(targLaddrHist)
	if err != nil {
		panic(err)
	}

	err = spec.Variables["targ_raddr_hist"].Set(targRaddrHist)
	if err != nil {
		panic(err)
	}

	err = spec.Variables["targ_show_ext"].Set(targShowExt)
	if err != nil {
		panic(err)
	}

	err = spec.Variables["targ_sport"].Set(targSport)
	if err != nil {
		panic(err)
	}

	err = spec.Variables["targ_dport"].Set(targDport)
	if err != nil {
		panic(err)
	}

	err = spec.Variables["targ_ms"].Set(targMs)
	if err != nil {
		panic(err)
	}

	// Parse and set source address if provided
	if targSaddr != "" {
		addr := net.ParseIP(targSaddr)
		if addr == nil {
			fmt.Printf("Invalid source address: %s\n", targSaddr)
			os.Exit(1)
		}
		if ipv4 := addr.To4(); ipv4 != nil {
			// Convert IPv4 to uint32
			saddr := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
			err = spec.Variables["targ_saddr"].Set(saddr)
			if err != nil {
				panic(err)
			}
		}
	}

	// Parse and set destination address if provided
	if targDaddr != "" {
		addr := net.ParseIP(targDaddr)
		if addr == nil {
			fmt.Printf("Invalid destination address: %s\n", targDaddr)
			os.Exit(1)
		}
		if ipv4 := addr.To4(); ipv4 != nil {
			// Convert IPv4 to uint32
			daddr := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
			err = spec.Variables["targ_daddr"].Set(daddr)
			if err != nil {
				panic(err)
			}
		}
	}
}

func printHistogram(obj *tcprttObjects) {
	// Iterate through the histogram map
	var key uint64
	var hist tcprttHist
	iter := obj.Hists.Iterate()

	for iter.Next(&key, &hist) {
		// Format the key (address or 0 for global)
		var keyStr string
		if key == 0 {
			keyStr = "Global"
		} else {
			// Convert key to IP address
			ip := make(net.IP, 4)
			ip[0] = byte(key >> 24)
			ip[1] = byte(key >> 16)
			ip[2] = byte(key >> 8)
			ip[3] = byte(key)
			keyStr = ip.String()
		}

		// Create description for the histogram
		timeUnit := "μs"
		if targMs {
			timeUnit = "ms"
		}
		description := fmt.Sprintf("RTT (%s) for %s", timeUnit, keyStr)

		// Convert hist.Slots array to slice and print using PrintLog2Hist
		slots := hist.Slots[:]
		utils.PrintLog2Hist(slots, description)

		// Show extension summary if requested
		if targShowExt && hist.Cnt > 0 {
			avg := hist.Latency / hist.Cnt
			fmt.Printf("Extension summary: avg=%d%s, count=%d\n", avg, timeUnit, hist.Cnt)
		}
		fmt.Println()
	}

	if err := iter.Err(); err != nil {
		fmt.Printf("Error iterating histogram: %v\n", err)
	}
}
