package main

import (
	"fmt"
	"io"
)

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
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	switch args[0] {
	case "inspect":
		return inspect(args[1:], stdout, stderr)
	case "login", "push", "pull", "run":
		fmt.Fprintf(stderr, "capm %s: not implemented yet\n", args[0])
		return 1
	default:
		fmt.Fprintf(stderr, "capm: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
