package main

import "fmt"

const (
	TCP_ESTABLISHED  = 1
	TCP_SYN_SENT     = 2
	TCP_SYN_RECV     = 3
	TCP_FIN_WAIT1    = 4
	TCP_FIN_WAIT2    = 5
	TCP_TIME_WAIT    = 6
	TCP_CLOSE        = 7
	TCP_CLOSE_WAIT   = 8
	TCP_LAST_ACK     = 9
	TCP_LISTEN       = 10
	TCP_CLOSING      = 11
	TCP_NEW_SYN_RECV = 12
)

var tcpStateNames = map[int32]string{
	TCP_ESTABLISHED:  "ESTABLISHED",
	TCP_SYN_SENT:     "SYN_SENT",
	TCP_SYN_RECV:     "SYN_RECV",
	TCP_FIN_WAIT1:    "FIN_WAIT1",
	TCP_FIN_WAIT2:    "FIN_WAIT2",
	TCP_TIME_WAIT:    "TIME_WAIT",
	TCP_CLOSE:        "CLOSE",
	TCP_CLOSE_WAIT:   "CLOSE_WAIT",
	TCP_LAST_ACK:     "LAST_ACK",
	TCP_LISTEN:       "LISTEN",
	TCP_CLOSING:      "CLOSING",
	TCP_NEW_SYN_RECV: "NEW_SYN_RECV",
}

func getTcpStateName(state int32) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}
