package api

import (
	"strconv"
	"strings"
)

type semver struct {
	major, minor, patch uint64
	pre                 []string
}

func parseSemver(s string) (semver, bool) {
	s, _, _ = strings.Cut(s, "+")
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var n [3]uint64
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil || p == "" || (len(p) > 1 && p[0] == '0') {
			return semver{}, false
		}
		n[i] = v
	}
	v := semver{major: n[0], minor: n[1], patch: n[2]}
	if hasPre {
		if pre == "" {
			return semver{}, false
		}
		v.pre = strings.Split(pre, ".")
		for _, id := range v.pre {
			if id == "" {
				return semver{}, false
			}
		}
	}
	return v, true
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compare orders by semver 2.0 precedence: -1, 0 or 1.
func (a semver) compare(b semver) int {
	if c := cmpU(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpU(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpU(a.patch, b.patch); c != 0 {
		return c
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if c := cmpU(xn, yn); c != 0 {
				return c
			}
		case xerr == nil:
			return -1
		case yerr == nil:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpU(uint64(len(a.pre)), uint64(len(b.pre)))
}
