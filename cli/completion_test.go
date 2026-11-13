package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

// --- the table cannot drift from the dispatch code -------------------------

// dispatchWords parses file and returns every lower-case word that fn
// compares against or switches on: the string literals of its case clauses
// and of its == comparisons. That is how run.go, cmd_admin.go, cmd_tokens.go
// and pin.go name their commands and subcommands, and parsing the source
// means the check needs neither to run a command nor a shared registry that
// the dispatch code would have to be refactored to use.
func dispatchWords(t *testing.T, file, fn string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	words := map[string]bool{}
	add := func(e ast.Expr) {
		if l, ok := e.(*ast.BasicLit); ok && l.Kind == token.STRING {
			s, _ := strconv.Unquote(l.Value)
			if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz-_") == "" {
				words[s] = true
			}
		}
	}
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CaseClause:
				for _, e := range n.List {
					add(e)
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL {
					add(n.X)
					add(n.Y)
				}
			}
			return true
		})
	}
	if !found {
		t.Fatalf("%s: no func %s (the completion drift test needs updating)", file, fn)
	}
	return words
}

func tableNames(specs []cmdSpec) map[string]bool {
	m := map[string]bool{}
	for _, s := range specs {
		m[s.Name] = true
	}
	return m
}

func findSpec(specs []cmdSpec, name string) *cmdSpec {
	for i := range specs {
		if specs[i].Name == name {
			return &specs[i]
		}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestCompletionTableMatchesDispatch(t *testing.T) {
	cases := []struct {
		file, fn string
		table    map[string]bool
		skip     map[string]bool
	}{
		// "help", "-h", "--help" are not words (the dash filter keeps "help"):
		// they are answered before the switch and are listed in hiddenCommands.
		{"run.go", "runCommand", tableNames(commandTable), hiddenCommands},
		{"cmd_admin.go", "admin", tableNames(findSpec(commandTable, "admin").Subs), nil},
		{"cmd_tokens.go", "tokens", tableNames(findSpec(commandTable, "tokens").Subs), nil},
		{"pin.go", "knownCmd", tableNames(findSpec(commandTable, "known").Subs), nil},
	}
	for _, c := range cases {
		got := dispatchWords(t, c.file, c.fn)
		for w := range c.skip {
			delete(got, w)
		}
		if !slices.Equal(sortedKeys(got), sortedKeys(c.table)) {
			t.Errorf("%s %s dispatches %v but the completion table has %v; update commandTable in completion_table.go",
				c.file, c.fn, sortedKeys(got), sortedKeys(c.table))
		}
	}
}

// flagNames returns the flag names registered on the flag.FlagSet named set
// in file (fs.BoolVar / StringVar / Var calls).
func flagNames(t *testing.T, file, set string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		mine := false
		ast.Inspect(fd, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewFlagSet" && len(c.Args) > 0 {
					if l, ok := c.Args[0].(*ast.BasicLit); ok && l.Value == strconv.Quote(set) {
						mine = true
					}
				}
			}
			return true
		})
		if !mine {
			return false
		}
		ast.Inspect(fd, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok || len(c.Args) < 2 || (sel.Sel.Name != "BoolVar" && sel.Sel.Name != "StringVar" && sel.Sel.Name != "Var") {
				return true
			}
			if l, ok := c.Args[1].(*ast.BasicLit); ok && l.Kind == token.STRING {
				s, _ := strconv.Unquote(l.Value)
				names[s] = true
			}
			return true
		})
		return false
	})
	return names
}

func TestCompletionTableFlagsMatchFlagSets(t *testing.T) {
	for cmd, file := range map[string]string{"init": "cmd_init.go", "run": "cmd_run.go", "lint": "cmd_lint.go", "push": "cmd_push.go"} {
		want := flagNames(t, file, cmd)
		if len(want) == 0 {
			t.Fatalf("%s: found no flags for %q; the drift test needs updating", file, cmd)
		}
		got := map[string]bool{}
		for _, f := range findSpec(commandTable, cmd).Flags {
			got[f.Name] = true
			if f.Short != "" {
				got[f.Short] = true
			}
		}
		if !slices.Equal(sortedKeys(want), sortedKeys(got)) {
			t.Errorf("capm %s: flags in %s are %v, completion table has %v", cmd, file, sortedKeys(want), sortedKeys(got))
		}
	}
}

func TestCompletionTableEnumsMatchCode(t *testing.T) {
	if got := strings.Join(sortValues, "|"); got != sortFlagValues {
		t.Errorf("sort values %q vs sortFlagValues %q", got, sortFlagValues)
	}
	if !slices.Equal(initBaseEnum(), manifest.BaseAgents) {
		t.Errorf("--base must complete manifest.BaseAgents")
	}
}

// --- capm completion ---------------------------------------------------------

func TestCompletionCommand(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish"} {
		var out, errb bytes.Buffer
		if code := runCommand([]string{"completion", sh}, &out, &errb, env{}); code != 0 {
			t.Fatalf("%s: exit %d: %s", sh, code, errb.String())
		}
		want, ok := completionScript(sh)
		if !ok || out.String() != want || errb.Len() != 0 {
			t.Errorf("%s: stdout differs from the generated script (stderr %q)", sh, errb.String())
		}
	}
	for _, args := range [][]string{{"completion"}, {"completion", "powershell"}, {"completion", "bash", "zsh"}, {"completion", "--help"}} {
		var out, errb bytes.Buffer
		if code := runCommand(args, &out, &errb, env{}); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		if out.Len() != 0 {
			t.Errorf("%v: wrote to stdout: %q", args, out.String())
		}
		for _, sh := range []string{"bash", "zsh", "fish"} {
			if !strings.Contains(errb.String(), sh) {
				t.Errorf("%v: usage error does not list %s: %q", args, sh, errb.String())
			}
		}
	}
}

func TestUsageListsCompletionButNotComplete(t *testing.T) {
	if !strings.Contains(usage, "completion") {
		t.Error("usage does not mention completion")
	}
	if strings.Contains(usage, "__complete") {
		t.Error("usage mentions the hidden __complete")
	}
}

// --- generated scripts: goldens, real-shell syntax checks -------------------

// Golden files live in testdata/completion. After changing the table or a
// generator, regenerate them with
//
//	CAPM_UPDATE_GOLDEN=1 go test ./cli -run TestCompletionGolden
//
// and review the diff.
var goldenNames = map[string]string{"bash": "capm.bash", "zsh": "_capm", "fish": "capm.fish"}

func TestCompletionGolden(t *testing.T) {
	for sh, name := range goldenNames {
		got, ok := completionScript(sh)
		if !ok {
			t.Fatalf("no generator for %s", sh)
		}
		path := filepath.Join("testdata", "completion", name)
		if os.Getenv("CAPM_UPDATE_GOLDEN") != "" {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (generate with CAPM_UPDATE_GOLDEN=1)", err)
		}
		if got != string(want) {
			t.Errorf("%s differs from %s; review and regenerate with CAPM_UPDATE_GOLDEN=1 go test ./cli -run TestCompletionGolden", sh, path)
		}
	}
}

func writeScript(t *testing.T, sh string) string {
	t.Helper()
	s, _ := completionScript(sh)
	p := filepath.Join(t.TempDir(), goldenNames[sh])
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCompletionScriptsPassSyntaxCheck(t *testing.T) {
	checks := []struct {
		sh   string
		args func(path string) []string
	}{
		{"bash", func(p string) []string { return []string{"-n", p} }},
		{"zsh", func(p string) []string { return []string{"-n", p} }},
		{"fish", func(p string) []string { return []string{"--no-execute", p} }},
	}
	for _, c := range checks {
		t.Run(c.sh, func(t *testing.T) {
			bin, err := exec.LookPath(c.sh)
			if err != nil {
				t.Skipf("%s is not installed; its generated script was NOT syntax-checked", c.sh)
			}
			p := writeScript(t, c.sh)
			if out, err := exec.Command(bin, c.args(p)...).CombinedOutput(); err != nil {
				t.Fatalf("%s rejects the script: %v\n%s", c.sh, err, out)
			}
		})
	}
	// macOS ships bash 3.2 as /bin/bash; check against it too when it is not
	// the bash on PATH.
	if p, err := exec.LookPath("bash"); err == nil && p != "/bin/bash" {
		if _, err := os.Stat("/bin/bash"); err == nil {
			if out, err := exec.Command("/bin/bash", "-n", writeScript(t, "bash")).CombinedOutput(); err != nil {
				t.Fatalf("/bin/bash rejects the script: %v\n%s", err, out)
			}
		}
	}
}

// --- functional: bash ---------------------------------------------------------

// fakeCapm writes a `capm` that answers `__complete bundles <prefix>` the way
// the real one would, and returns the directory to put on PATH.
func fakeCapm(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = __complete ] && [ "$2" = bundles ]; then
  case "$3" in
    alice/*) echo alice/one; echo alice/two ;;
    a*) echo alice/one; echo alice2/x ;;
  esac
fi
`
	if err := os.WriteFile(filepath.Join(dir, "capm"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func bashBinaries() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range []string{"bash", "/bin/bash"} {
		if p, err := exec.LookPath(c); err == nil && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// bashReply sources the generated script in a clean bash and returns the
// COMPREPLY for a command line given as words, the last being the word under
// the cursor (as COMP_WORDS has it, "" for a cursor after a space).
func bashReply(t *testing.T, bash, cwd string, words ...string) []string {
	t.Helper()
	return bashReplyPre(t, bash, cwd, "", words...)
}

// bashReplyPre is bashReply with shell text run before the script is sourced
// (the directory test uses it to stand in for bash 4's compopt on bash 3.2).
func bashReplyPre(t *testing.T, bash, cwd, prelude string, words ...string) []string {
	t.Helper()
	const prog = `pre=$1; shift; eval "$pre"; src=$1; cw=$2; shift 2
source "$src" || exit 9
COMP_WORDS=("$@"); COMP_CWORD=$cw; COMP_LINE="$*"; COMP_POINT=${#COMP_LINE}
_capm
for r in "${COMPREPLY[@]}"; do [ -n "$r" ] && printf '%s\n' "$r"; done
exit 0`
	args := append([]string{"--norc", "--noprofile", "-c", prog, "_", prelude, writeScript(t, "bash"), strconv.Itoa(len(words) - 1)}, words...)
	cmd := exec.Command(bash, args...)
	cmd.Dir = cwd
	cmd.Env = []string{"PATH=" + fakeCapm(t) + ":/usr/bin:/bin", "HOME=" + t.TempDir(), "LC_ALL=C"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %q: %v\n%s", bash, words, err, stderr.String())
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			got = append(got, l)
		}
	}
	sort.Strings(got)
	return got
}

func TestBashCompletionFunctional(t *testing.T) {
	bashes := bashBinaries()
	if len(bashes) == 0 {
		t.Skip("bash is not installed; the bash completion function was NOT exercised")
	}
	cmds := func() []string {
		var out []string
		for _, c := range commandTable {
			if !c.Hidden {
				out = append(out, c.Name)
			}
		}
		sort.Strings(out)
		return out
	}()
	cases := []struct {
		name  string
		words []string
		want  []string
	}{
		{"commands", []string{"capm", ""}, cmds},
		{"prefix li", []string{"capm", "li"}, []string{"lint", "list"}},
		{"sort values", []string{"capm", "list", "--sort", ""}, []string{"downloads", "name", "recent"}},
		{"sort prefix", []string{"capm", "list", "--sort", "re"}, []string{"recent"}},
		{"sort= form", []string{"capm", "list", "--sort", "=", "re"}, []string{"recent"}},
		{"sort= bare", []string{"capm", "list", "--sort", "="}, []string{"downloads", "name", "recent"}},
		{"admin subs", []string{"capm", "admin", ""}, []string{"ban", "log", "quota", "remove", "report", "reports", "resolve", "restore", "revoke-tokens", "unban"}},
		{"admin flags", []string{"capm", "admin", "remove", "alice/x", "--"}, []string{"--reason"}},
		{"bundle refs", []string{"capm", "run", "alice/"}, []string{"alice/one", "alice/two"}},
		{"bundle refs pull", []string{"capm", "pull", "a"}, []string{"alice/one", "alice2/x"}},
		{"run flags", []string{"capm", "run", "--al"}, []string{"--allow-global-anthropic-secret", "--allow-unenforced-egress"}},
		{"report reason", []string{"capm", "report", "alice/x", "--reason", ""}, []string{"impersonation", "malware", "other", "secrets-exposed"}},
		{"init base", []string{"capm", "init", "--base", ""}, []string{"claude-code", "opencode"}},
		{"completion shells", []string{"capm", "completion", ""}, []string{"bash", "fish", "zsh"}},
		{"completion only once", []string{"capm", "completion", "bash", ""}, nil},
		{"tokens sub", []string{"capm", "tokens", ""}, []string{"revoke"}},
		{"tokens id: nothing", []string{"capm", "tokens", "revoke", ""}, nil},
		{"known forget refs", []string{"capm", "known", "forget", "alice/"}, []string{"alice/one", "alice/two"}},
		{"list owner: nothing", []string{"capm", "list", ""}, nil},
		{"free value flag: nothing", []string{"capm", "run", "--model", ""}, nil},
		{"unknown command: nothing", []string{"capm", "nosuch", ""}, nil},
		{"version: nothing", []string{"capm", "version", ""}, nil},
	}
	for _, bash := range bashes {
		for _, c := range cases {
			t.Run(filepath.Base(bash)+"/"+c.name, func(t *testing.T) {
				got := bashReply(t, bash, t.TempDir(), c.words...)
				if !slices.Equal(got, c.want) {
					t.Errorf("%q\n got  %q\n want %q", c.words, got, c.want)
				}
			})
		}
	}
}

func TestBashDirectoryCompletion(t *testing.T) {
	bashes := bashBinaries()
	if len(bashes) == 0 {
		t.Skip("bash is not installed")
	}
	cwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, "mybundle"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "mybundle.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, bash := range bashes {
		// bash >= 4 completes directories itself (compgen -d); bash 3.2 has no
		// compopt, so the script registers "-o default" and leaves COMPREPLY
		// empty so readline completes file names.
		got := bashReply(t, bash, cwd, "capm", "push", "my")
		out, _ := exec.Command(bash, "-c", `type compopt >/dev/null 2>&1 && echo yes || echo no`).Output()
		want := []string(nil)
		if strings.TrimSpace(string(out)) == "yes" {
			want = []string{"mybundle"}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: push my -> %q, want %q", bash, got, want)
		}
		// The bash >= 4 branch, with a no-op compopt standing in for the
		// builtin so it can run on bash 3.2 (compgen -d itself exists there).
		if got := bashReplyPre(t, bash, cwd, "compopt() { :; }", "capm", "push", "my"); !slices.Equal(got, []string{"mybundle"}) {
			t.Errorf("%s: push my with compopt -> %q, want [mybundle]", bash, got)
		}
		// a path-looking word for run never asks the registry
		if got := bashReply(t, bash, cwd, "capm", "run", "./my"); slices.Contains(got, "alice/one") {
			t.Errorf("%s: ./my asked for registry refs: %q", bash, got)
		}
	}
}

func TestBashScriptRegistersCompletion(t *testing.T) {
	bashes := bashBinaries()
	if len(bashes) == 0 {
		t.Skip("bash is not installed")
	}
	for _, bash := range bashes {
		out, err := exec.Command(bash, "--norc", "--noprofile", "-c", `source "$1" && complete -p capm`, "_", writeScript(t, "bash")).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "-F _capm capm") {
			t.Errorf("%s: complete -p capm: %q (%v)", bash, out, err)
		}
		// The documented one-liner is eval "$(capm completion bash)": bash 3.2
		// cannot "source <(...)", so the script must also work when eval'd.
		script, _ := completionScript("bash")
		out, err = exec.Command(bash, "--norc", "--noprofile", "-c", `eval "$1" && complete -p capm`, "_", script).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "-F _capm capm") {
			t.Errorf("%s: eval of the script: %q (%v)", bash, out, err)
		}
	}
}

// --- functional: zsh (no TTY) -------------------------------------------------

// zshReply sources the script in `zsh -f`, replaces the completion builtins
// (compadd, _describe, _files, compset, compdef) with stubs that print what
// they were given, and calls _capm with words/CURRENT set as the completion
// system would. It exercises the function's logic, not zsh's matcher or
// compinit; the real thing needs a pty.
func zshReply(t *testing.T, zsh string, words ...string) []string {
	t.Helper()
	const prog = `src=$1; cur=$2; shift 2
compdef() { : }
source $src || exit 9
compadd() { local a; while [[ $1 == -* && $1 != -- ]]; do shift; done; [[ $1 == -- ]] && shift; for a; do print -r -- "$a"; done }
_describe() { local e; for e in "${(@P)2}"; do print -r -- "${e%%:*}"; done }
_files() { print -r -- "FILES $*" }
compset() { return 1 }
words=("$@"); CURRENT=$cur; PREFIX=${words[CURRENT]}
_capm
exit 0`
	cmd := exec.Command(zsh, "-f", "-c", prog, "_", writeScript(t, "zsh"), strconv.Itoa(len(words)))
	cmd.Args = append(cmd.Args, words...)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=" + fakeCapm(t) + ":/usr/bin:/bin", "HOME=" + t.TempDir()}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("zsh %q: %v\n%s", words, err, stderr.String())
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			got = append(got, l)
		}
	}
	sort.Strings(got)
	return got
}

func TestZshCompletionFunctional(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh is not installed; the zsh completion function was NOT exercised")
	}
	cmds := []string{}
	for _, c := range commandTable {
		if !c.Hidden {
			cmds = append(cmds, c.Name)
		}
	}
	sort.Strings(cmds)
	cases := []struct {
		name  string
		words []string
		want  []string
	}{
		{"commands", []string{"capm", ""}, cmds},
		{"sort values", []string{"capm", "list", "--sort", ""}, []string{"downloads", "name", "recent"}},
		{"admin subs", []string{"capm", "admin", ""}, []string{"ban", "log", "quota", "remove", "report", "reports", "resolve", "restore", "revoke-tokens", "unban"}},
		{"bundle refs and dirs", []string{"capm", "run", "alice/"}, []string{"FILES -/", "alice/one", "alice/two"}},
		{"run flags", []string{"capm", "run", "--al"}, []string{"--allow-global-anthropic-secret", "--allow-unenforced-egress"}},
		{"report reason", []string{"capm", "report", "alice/x", "--reason", ""}, []string{"impersonation", "malware", "other", "secrets-exposed"}},
		{"completion shells", []string{"capm", "completion", ""}, []string{"bash", "fish", "zsh"}},
		{"push dir", []string{"capm", "push", ""}, []string{"FILES -/"}},
		{"free flag value: nothing", []string{"capm", "run", "--model", ""}, nil},
		{"unknown command: nothing", []string{"capm", "nosuch", ""}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := zshReply(t, zsh, c.words...)
			// zsh filters by the word under the cursor itself (compadd), so
			// the stub returns every candidate; narrow to the prefix here.
			cur := c.words[len(c.words)-1]
			var filtered []string
			for _, g := range got {
				if strings.HasPrefix(g, cur) || strings.HasPrefix(g, "FILES") {
					filtered = append(filtered, g)
				}
			}
			if !slices.Equal(filtered, c.want) {
				t.Errorf("%q\n got  %q\n want %q", c.words, filtered, c.want)
			}
		})
	}
}

func TestZshScriptSourcedRegistersWithCompdef(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh is not installed")
	}
	out, err := exec.Command(zsh, "-f", "-c", `compdef() { print -r -- "COMPDEF $*" }; source "$1"`, "_", writeScript(t, "zsh")).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "COMPDEF _capm capm") {
		t.Errorf("sourcing did not run compdef _capm capm: %q (%v)", out, err)
	}
}

func TestScriptsCallBackIntoComplete(t *testing.T) {
	for sh := range goldenNames {
		s, _ := completionScript(sh)
		if !strings.Contains(s, "__complete bundles") {
			t.Errorf("%s script does not call back into __complete bundles", sh)
		}
	}
}

func initBaseEnum() []string {
	for _, f := range findSpec(commandTable, "init").Flags {
		if f.Name == "base" {
			return f.Enum
		}
	}
	return nil
}
