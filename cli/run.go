package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// env carries everything the networked commands need, so tests can inject it.
type env struct {
	registry string              // registry base URL
	credDir  string              // directory holding credentials.json
	sleep    func(time.Duration) // used while polling for login
}

func defaultEnv() env {
	e := env{registry: os.Getenv("CAPM_REGISTRY"), sleep: time.Sleep}
	if e.registry == "" {
		e.registry = "http://localhost:8080"
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
  pull      Fetch an agent and verify its signature
  inspect   Show the enforced permission summary
  run       Launch an agent in a sandbox
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
		fmt.Fprintf(stderr, "capm %s: not implemented yet\n", args[0])
		return 1
	default:
		fmt.Fprintf(stderr, "capm: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
