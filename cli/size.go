package main

import (
	"fmt"
	"strconv"
	"strings"
)

// maxSize bounds a size argument (1 PiB), well inside int64.
const maxSize = 1 << 50

var sizeUnits = map[string]int64{
	"": 1, "b": 1,
	"k": 1 << 10, "kib": 1 << 10, "m": 1 << 20, "mib": 1 << 20, "g": 1 << 30, "gib": 1 << 30, "t": 1 << 40, "tib": 1 << 40,
	"kb": 1000, "mb": 1000 * 1000, "gb": 1000 * 1000 * 1000, "tb": 1000 * 1000 * 1000 * 1000,
}

// parseSize reads a whole number of bytes: plain ("524288000") or with a unit
// ("500MiB", "2GiB"). KiB/MiB/GiB/TiB (and K/M/G/T) are powers of 1024,
// KB/MB/GB/TB powers of 1000. Fractions and negatives are refused.
func parseSize(s string) (int64, error) {
	t := strings.TrimSpace(s)
	i := 0
	for i < len(t) && t[i] >= '0' && t[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("%q is not a size (use a whole number of bytes, or e.g. 500MiB or 2GiB)", s)
	}
	n, err := strconv.ParseInt(t[:i], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is too large", s)
	}
	mult, ok := sizeUnits[strings.ToLower(strings.TrimSpace(t[i:]))]
	if !ok {
		return 0, fmt.Errorf("%q is not a size (use a whole number of bytes, or e.g. 500MiB or 2GiB)", s)
	}
	if n > maxSize/mult {
		return 0, fmt.Errorf("%q is too large (the limit is 1 PiB)", s)
	}
	return n * mult, nil
}

// humanBytes formats n in binary units, e.g. "100.0 MiB".
func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		f /= 1024
		if f < 1024 || u == "TiB" {
			return fmt.Sprintf("%.1f %s", f, u)
		}
	}
	return ""
}
