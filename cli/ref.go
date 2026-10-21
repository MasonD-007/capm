package main

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	segRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

// parseRef parses "user/name", "user/name@1.2.3" or "user/name@latest".
// The version defaults to "latest".
func parseRef(s string) (owner, name, version string, err error) {
	ref, ver, hasVer := strings.Cut(s, "@")
	parts := strings.Split(ref, "/")
	if len(parts) != 2 || !segRe.MatchString(parts[0]) || !segRe.MatchString(parts[1]) ||
		strings.Contains(ref, "..") {
		return "", "", "", fmt.Errorf("invalid reference %q (want user/name[@version])", s)
	}
	version = "latest"
	if hasVer {
		if !versionRe.MatchString(ver) || strings.Contains(ver, "..") {
			return "", "", "", fmt.Errorf("invalid version in %q", s)
		}
		version = ver
	}
	return parts[0], parts[1], version, nil
}
