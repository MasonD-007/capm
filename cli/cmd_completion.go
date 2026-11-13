package main

import (
	"fmt"
	"io"
	"strings"
)

// completion implements `capm completion bash|zsh|fish`: it prints the script
// (generated from commandTable, see completion_gen.go) to stdout.
func completion(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) == 1 {
		if s, ok := completionScript(args[0]); ok {
			io.WriteString(stdout, s)
			return 0
		}
	}
	fmt.Fprintf(stderr, "usage: capm completion <%s>\n"+
		"  Prints a completion script for the shell; for example\n"+
		"    bash: source <(capm completion bash)\n"+
		"    zsh:  source <(capm completion zsh)   (after compinit)\n"+
		"    fish: capm completion fish | source\n",
		strings.Join(completionShells, "|"))
	return 2
}
