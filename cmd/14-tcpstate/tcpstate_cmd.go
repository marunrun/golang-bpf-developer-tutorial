package main

import (
	"github.com/spf13/cobra"
)

// tcpstate command flags
var (
	targetFamily  string
	filterBySport bool
	filterByDport bool
	sportsList    portList
	dportsList    portList
)

// tcpstateCmd represents the tcpstate command
var tcpstateCmd = &cobra.Command{
	Use:   "tcpstate",
	Short: "Monitor TCP state changes",
	Long: `tcpstate - Monitor TCP state changes

This tool monitors TCP state changes in the system and displays information about each state transition.
It can filter connections by IP family, source ports, and destination ports.`,
	Run: runTcpState,
}

func init() {
	// 设置 tcpstate 命令行参数
	tcpstateCmd.Flags().StringVarP(&targetFamily, "target_family", "f", "ipv4", "Target IP family to filter (ipv4 or ipv6)")
	tcpstateCmd.Flags().BoolVarP(&filterBySport, "filter_by_sport", "s", false, "Enable filtering by source ports")
	tcpstateCmd.Flags().BoolVarP(&filterByDport, "filter_by_dport", "d", false, "Enable filtering by destination ports")
	tcpstateCmd.Flags().Var(&sportsList, "sports", "Comma-separated list of source ports to filter (e.g., 22,80,443)")
	tcpstateCmd.Flags().Var(&dportsList, "dports", "Comma-separated list of destination ports to filter (e.g., 22,80,443)")
}
