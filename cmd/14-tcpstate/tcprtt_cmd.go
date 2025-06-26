package main

import (
	"github.com/spf13/cobra"
)

// tcprtt command flags
var (
	targLaddrHist bool
	targRaddrHist bool
	targShowExt   bool
	targSport     uint16
	targDport     uint16
	targSaddr     string
	targDaddr     string
	targMs        bool
)

// tcprttCmd represents the tcprtt command
var tcprttCmd = &cobra.Command{
	Use:   "tcprtt",
	Short: "Monitor TCP round-trip time",
	Long: `tcprtt - Monitor TCP round-trip time (RTT)

This tool monitors TCP round-trip time statistics and displays histogram data.
It can filter connections by source/destination addresses and ports.`,
	Run: runTcprtt,
}

func init() {
	// 设置 tcprtt 命令行参数
	tcprttCmd.Flags().BoolVarP(&targLaddrHist, "laddr-hist", "l", false, "Show histogram by local address")
	tcprttCmd.Flags().BoolVarP(&targRaddrHist, "raddr-hist", "r", false, "Show histogram by remote address")
	tcprttCmd.Flags().BoolVarP(&targShowExt, "extension", "e", false, "Show extension summary")
	tcprttCmd.Flags().Uint16VarP(&targSport, "sport", "s", 0, "Filter by source port")
	tcprttCmd.Flags().Uint16VarP(&targDport, "dport", "d", 0, "Filter by destination port")
	tcprttCmd.Flags().StringVar(&targSaddr, "saddr", "", "Filter by source address")
	tcprttCmd.Flags().StringVar(&targDaddr, "daddr", "", "Filter by destination address")
	tcprttCmd.Flags().BoolVarP(&targMs, "milliseconds", "m", false, "Show RTT in milliseconds instead of microseconds")
}
