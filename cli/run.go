package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/MasonD-007/capm/cli/internal/sbx"
)

// env carries everything the networked commands need, so tests can inject it.
type env struct {
	registry string              // registry base URL
	credDir  string              // directory holding credentials.json
	sleep    func(time.Duration) // used while polling for login

	// capm run; nil fields get real defaults (see runDefaults).
	ctx        context.Context
	stdin      io.Reader
	isTTY      func() bool
	getenv     func(string) string
	readSecret func(prompt string) (string, error) // no-echo prompt
	runner     sbx.Runner
	tempRoot   string // parent for temp dirs; "" means os.TempDir()
}

const defaultRegistry = "https://capm.masondrake.dev"

func defaultEnv() env {
	e := env{registry: os.Getenv("CAPM_REGISTRY"), sleep: time.Sleep}
	if e.registry == "" {
		e.registry = defaultRegistry
	}
	if d, err := os.UserConfigDir(); err == nil {
		e.credDir = filepath.Join(d, "capm")
	}
	return e
}

const usage = `capm: share AI agents and run them in a sandbox

Usage:
  capm <command> [args]

Commands:
  login     Authenticate with a registry
  push      Package and publish an agent to a registry
  pull      Download a bundle and check it against the registry's sha256 digest (bundles are not signed)
  inspect   Show the bundle's declared permissions (not enforced; see the egress line)
  run       Launch an agent in a Docker Sandbox (sbx)

capm run [--yes] [--workdir DIR] [--model-url URL] [--model-key KEY] [--model NAME]
         [--allow-unenforced-egress] [--allow-global-anthropic-secret] <dir | user/name[@version]>
  Shows the declared permissions and run plan, asks to confirm (--yes skips),
  then runs the agent with sbx. Mount paths are relative to --workdir
  (default: the current directory). The model endpoint comes from --model-url
  / --model-key / --model or CAPM_MODEL_URL / CAPM_MODEL_KEY / CAPM_MODEL.
  Each declared secret NAME is read from CAPM_SECRET_<NAME>, else prompted
  for without echo (never from the sbx secret store). capm cannot yet enforce
  exact-host egress, so run refuses to start unless --allow-unenforced-egress
  is given. It also refuses when a global sbx "anthropic" secret is stored,
  since the sandbox can reach api.anthropic.com, unless
  --allow-global-anthropic-secret is given.
`

// run executes the CLI with args (excluding the program name) and returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	return runEnv(args, stdout, stderr, defaultEnv())
}

func runEnv(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	switch args[0] {
	case "inspect":
		return inspect(args[1:], stdout, stderr, e)
	case "login":
		return login(args[1:], stdout, stderr, e)
	case "push":
		return push(args[1:], stdout, stderr, e)
	case "pull":
		return pull(args[1:], stdout, stderr, e)
	case "run":
		return runCmd(args[1:], stdout, stderr, e)
	default:
		fmt.Fprintf(stderr, "capm: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
