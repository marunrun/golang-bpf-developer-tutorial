package utils

import (
	"bytes"
	"fmt"
	"golang.org/x/exp/constraints"
	"strings"
)

func printStars[T constraints.Integer](b *bytes.Buffer, val, maxVal T, width int) {
	var nStars, nSpaces int
	var needPlus bool

	nStars = int(min(val, maxVal) * T(width) / maxVal)
	nSpaces = width - nStars
	needPlus = val > maxVal

	_, _ = fmt.Fprint(b, strings.Repeat("*", nStars))
	_, _ = fmt.Fprint(b, strings.Repeat(" ", nSpaces))

	if needPlus {
		_, _ = fmt.Fprint(b, "+")
	}
}

func PrintLog2Hist[T constraints.Integer](vals []T, valType string) {
	var idxMax = -1
	var valMax T

	for i, v := range vals {
		if v > 0 {
			idxMax = i
		}
		if v > valMax {
			valMax = v
		}
	}

	if idxMax < 0 {
		return
	}

	if idxMax <= 32 {
		fmt.Printf("%5s%-19s : %-13s distribution\n", "", valType, "count")
	} else {
		fmt.Printf("%15s%-29s : %-13s distribution\n", "", valType, "count")
	}

	var stars int
	if idxMax <= 32 {
		stars = 40
	} else {
		stars = 20
	}

	for i := 0; i <= idxMax; i++ {
		low, high := (uint64(1)<<(i+1))>>1, (uint64(1)<<(i+1))-1
		if low == high {
			low -= 1
		}

		var b bytes.Buffer

		val := vals[i]
		if idxMax <= 32 {
			fmt.Fprintf(&b, "%10d -> %-10d : %-13d |", low, high, val)
		} else {
			fmt.Fprintf(&b, "%20d -> %-20d : %-13d |", low, high, val)
		}

		printStars(&b, val, valMax, stars)

		fmt.Fprint(&b, "|\n")

		fmt.Print(b.String())
	}
}
