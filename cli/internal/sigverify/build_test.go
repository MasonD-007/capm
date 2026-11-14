package sigverify

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The release builds four targets with CGO_ENABLED=0 (scripts/build-cli.sh).
// This compiles this package, and so every dependency it pulls in, for all
// four, so a dependency that needs cgo (or lacks a pure-Go fallback on one
// target) fails here rather than at release time. Compile only, no link, so
// it is cheap once the build cache is warm. Skipped with -short, and outside CI
// unless SIGVERIFY_CROSS_BUILD is set.
func TestBuildsWithoutCGOForReleaseTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiles four targets; skipped with -short")
	}
	if os.Getenv("CI") == "" && os.Getenv("SIGVERIFY_CROSS_BUILD") == "" {
		t.Skip("runs in CI (CI is set) or with SIGVERIFY_CROSS_BUILD=1; compiling four targets is slow on a cold cache")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	for _, target := range []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"} {
		os_, arch, _ := strings.Cut(target, "/")
		t.Run(target, func(t *testing.T) {
			cmd := exec.Command("go", "build", ".")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+os_, "GOARCH="+arch)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("go build for %s failed: %v\n%s", target, err, out)
			}
		})
	}
}
