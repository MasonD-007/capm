package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/MasonD-007/capm/manifest"
)

const initUse = "usage: capm init [dir] [--yes] [--name NAME] [--description TEXT] [--author NAME]... [--base AGENT]\n" +
	"                 [--base-version TAG] [--egress HOST]... [--mount PATH[:MODE]]... [--secret NAME]... [--repository URL]"

// Defaults. The base version is the kit tag the bundled example uses; the
// other agent has no tag known to this repo, so "latest" is a placeholder the
// author should replace (capm lint cannot check tags without running sbx).
const (
	defaultBaseVersion  = "2.1.292"
	fallbackBaseVersion = "latest"
	starterPromptPath   = "prompts/system.md"
	starterPrompt       = "# System prompt\n\nDescribe what this agent does and how it should behave.\n"
)

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

// initSpec is everything the manifest template needs.
type initSpec struct {
	name, description string
	repository        string // optional metadata.repository
	authors           []string
	base, baseVersion string
	egress            []string
	mounts            []manifest.Mount
	secrets           []string
	mcp               []manifest.MCP
	prompt            bool
}

var errInputEnded = errors.New("input ended before all questions were answered")

func initCmd(args []string, stdout, stderr io.Writer, e env) int {
	e = e.runDefaults(stdout, stderr)
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		yes                                         bool
		name, description, base, baseVersion        string
		repository                                  string
		authors, egress, mountFlags, secretFlagVals multiFlag
	)
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&yes, "y", false, "")
	fs.StringVar(&name, "name", "", "")
	fs.StringVar(&description, "description", "", "")
	fs.StringVar(&base, "base", "", "")
	fs.StringVar(&baseVersion, "base-version", "", "")
	fs.StringVar(&repository, "repository", "", "")
	fs.Var(&authors, "author", "")
	fs.Var(&egress, "egress", "")
	fs.Var(&mountFlags, "mount", "")
	fs.Var(&secretFlagVals, "secret", "")
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			fmt.Fprintf(stderr, "capm init: %v\n%s\n", err, initUse)
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) > 1 {
		fmt.Fprintln(stderr, initUse)
		return 2
	}
	dir := "."
	if len(pos) == 1 {
		dir = pos[0]
	}
	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "capm init: "+format+"\n", a...)
		return 2
	}

	// Validate flag values before anything else, so a typo writes nothing.
	spec := initSpec{description: description, authors: authors, egress: egress, baseVersion: baseVersion}
	if name != "" {
		if !manifest.ValidName(name) {
			return usageErr("--name %q must match a lowercase letter or digit followed by lowercase letters, digits or '-' (64 characters at most)", shown(name))
		}
		spec.name = name
	}
	if base != "" {
		if !contains(manifest.BaseAgents, base) {
			return usageErr("--base %q must be %s", shown(base), strings.Join(manifest.BaseAgents, " or "))
		}
		spec.base = base
	}
	if err := checkText("--description", description); err != nil {
		return usageErr("%v", err)
	}
	if repository != "" {
		if _, _, ok := manifest.ParseRepository(repository); !ok {
			return usageErr("--repository %q must be https://github.com/<owner>/<repo> exactly (no trailing slash, .git, query or fragment)", shown(repository))
		}
		spec.repository = repository
	}
	for _, a := range authors {
		if strings.TrimSpace(a) == "" {
			return usageErr("--author must not be empty")
		}
		if err := checkText("--author", a); err != nil {
			return usageErr("%v", err)
		}
	}
	if baseVersion != "" {
		if err := checkBaseVersion(baseVersion); err != nil {
			return usageErr("--base-version %v", err)
		}
	}
	for _, h := range egress {
		if !manifest.ValidHost(h) {
			return usageErr("--egress %q must be a lowercase hostname (exact name, no wildcard, no IP address)", shown(h))
		}
	}
	for _, f := range mountFlags {
		m, err := parseMountFlag(f)
		if err != nil {
			return usageErr("--mount %q: %v", shown(f), err)
		}
		spec.mounts = append(spec.mounts, m)
	}
	for _, s := range secretFlagVals {
		if !manifest.ValidSecretName(s) {
			return usageErr("--secret %q must be UPPER_SNAKE_CASE (start with a capital letter; capitals, digits and '_' only)", shown(s))
		}
		spec.secrets = append(spec.secrets, s)
	}
	spec.egress, spec.secrets = dedupe(spec.egress), dedupe(spec.secrets)

	interactive := !yes && e.isTTY()
	if !yes && !interactive {
		fmt.Fprintln(stderr, "capm init: stdin is not a terminal; pass --yes to accept the defaults (and flags such as --name) without questions")
		return 1
	}

	target := filepath.Join(dir, manifest.FileName)
	if _, err := os.Lstat(target); err == nil {
		fmt.Fprintf(stderr, "capm init: %s already exists; nothing was written\n", shown(target))
		return 1
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stderr, "capm init: %s\n", shown(err.Error()))
		return 1
	}

	if spec.name == "" {
		spec.name = defaultBundleName(dir)
	}
	if spec.base == "" {
		spec.base = manifest.BaseAgents[0]
	}
	if interactive {
		if err := askSpec(bufio.NewReader(e.stdin), stdout, &spec, baseVersion != ""); err != nil {
			fmt.Fprintf(stderr, "capm init: %v; nothing was written\n", err)
			return 1
		}
	} else {
		spec.prompt = true
		if spec.baseVersion == "" {
			spec.baseVersion = baseVersionFor(spec.base)
		}
	}

	text := renderManifest(spec)
	// A generated manifest that does not load and validate is a bug in init.
	if m, err := manifest.Parse([]byte(text)); err != nil {
		fmt.Fprintf(stderr, "capm init: internal error: generated manifest does not parse: %v\n", err)
		return 1
	} else if err := m.Validate(); err != nil {
		fmt.Fprintf(stderr, "capm init: internal error: generated manifest is invalid:\n%v\n", err)
		return 1
	}

	created, err := writeBundle(dir, text, spec.prompt)
	if err != nil {
		fmt.Fprintf(stderr, "capm init: %s\n", shown(err.Error()))
		return 1
	}
	fmt.Fprintln(stdout, "\nCreated:")
	for _, c := range created {
		fmt.Fprintf(stdout, "  %s\n", shown(c))
	}
	fmt.Fprintln(stdout, "\nNext steps:")
	if dir != "." {
		fmt.Fprintf(stdout, "  cd %s\n", shown(dir))
	}
	fmt.Fprint(stdout, "  capm lint        check the bundle for problems\n"+
		"  capm inspect .   see the permissions you are declaring\n"+
		"  capm login       sign in to the registry\n"+
		"  capm push .      publish it\n")
	return 0
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	var out []string
	for _, s := range in {
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func baseVersionFor(agent string) string {
	if agent == "claude-code" {
		return defaultBaseVersion
	}
	return fallbackBaseVersion
}

// checkText rejects text the manifest validator would (control characters).
func checkText(what, s string) error {
	if manifest.DisplaySafe(s) != s {
		return fmt.Errorf("%s must not contain control characters", what)
	}
	return nil
}

func checkBaseVersion(v string) error {
	if v == "" || strings.IndexFunc(v, unicode.IsSpace) >= 0 || manifest.DisplaySafe(v) != v {
		return errors.New("must be non-empty and contain no whitespace")
	}
	return nil
}

func parseMountFlag(f string) (manifest.Mount, error) {
	p, mode := f, "read-only"
	if i := strings.LastIndex(f, ":"); i >= 0 {
		p, mode = f[:i], f[i+1:]
	}
	if !manifest.ValidMountPath(p) {
		return manifest.Mount{}, errors.New("path must be a relative path inside the workspace")
	}
	if mode != "read-only" && mode != "read-write" {
		return manifest.Mount{}, errors.New("mode must be read-only or read-write (form: path:mode)")
	}
	return manifest.Mount{Path: p, Mode: mode}, nil
}

var nonNameChars = regexp.MustCompile(`[^a-z0-9]+`)

// defaultBundleName turns the directory name into something metadata.name
// accepts, falling back to "my-bundle".
func defaultBundleName(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "my-bundle"
	}
	n := nonNameChars.ReplaceAllString(strings.ToLower(filepath.Base(abs)), "-")
	n = strings.Trim(n, "-")
	if len(n) > 64 {
		n = strings.Trim(n[:64], "-")
	}
	if !manifest.ValidName(n) {
		return "my-bundle"
	}
	return n
}

// --- interactive questions -------------------------------------------------

type prompter struct {
	r   *bufio.Reader
	out io.Writer
}

// line asks one question and returns the trimmed answer, or def when blank.
func (p *prompter) line(question, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", question, shown(def))
	} else {
		fmt.Fprintf(p.out, "%s: ", question)
	}
	s, err := p.r.ReadString('\n')
	if err != nil && s == "" {
		return "", errInputEnded
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	return s, nil
}

// ask repeats the question until check accepts the answer.
func (p *prompter) ask(question, def string, check func(string) error) (string, error) {
	for {
		s, err := p.line(question, def)
		if err != nil {
			return "", err
		}
		if err := check(s); err != nil {
			fmt.Fprintf(p.out, "  %v\n", err)
			continue
		}
		return s, nil
	}
}

// askList asks for a comma-separated list; check validates each item and the
// whole line is asked again if any item is rejected. "none" or "-" clears it.
func (p *prompter) askList(question string, def []string, check func(string) error) ([]string, error) {
	for {
		s, err := p.line(question, strings.Join(def, ", "))
		if err != nil {
			return nil, err
		}
		if s == "none" || s == "-" {
			return nil, nil
		}
		var items []string
		ok := true
		for _, it := range strings.Split(s, ",") {
			if it = strings.TrimSpace(it); it == "" {
				continue
			}
			if err := check(it); err != nil {
				fmt.Fprintf(p.out, "  %v\n", err)
				ok = false
				break
			}
			items = append(items, it)
		}
		if ok {
			return dedupe(items), nil
		}
	}
}

func (p *prompter) yesNo(question string, def bool) (bool, error) {
	d := "Y/n"
	if !def {
		d = "y/N"
	}
	for {
		s, err := p.line(question+" ("+d+")", "")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(p.out, "  please answer y or n")
	}
}

// choose offers a numbered list; the answer may be the number or the item.
func (p *prompter) choose(question string, items []string, def string) (string, error) {
	fmt.Fprintln(p.out, question)
	defNum := "1"
	for i, it := range items {
		fmt.Fprintf(p.out, "  %d) %s\n", i+1, it)
		if it == def {
			defNum = strconv.Itoa(i + 1)
		}
	}
	for {
		s, err := p.line("Choice", defNum)
		if err != nil {
			return "", err
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(items) {
			return items[n-1], nil
		}
		if contains(items, s) {
			return s, nil
		}
		fmt.Fprintf(p.out, "  enter a number from 1 to %d\n", len(items))
	}
}

// askSpec fills spec from the terminal. Values already in spec (from flags or
// defaults) are offered as the defaults.
func askSpec(r *bufio.Reader, out io.Writer, spec *initSpec, versionFromFlag bool) error {
	p := &prompter{r: r, out: out}
	var err error
	textCheck := func(what string) func(string) error {
		return func(s string) error { return checkText(what, s) }
	}
	if spec.name, err = p.ask("Bundle name", spec.name, func(s string) error {
		if !manifest.ValidName(s) {
			return errors.New("use lowercase letters, digits and '-', starting with a letter or digit (64 characters at most)")
		}
		return nil
	}); err != nil {
		return err
	}
	if spec.description, err = p.ask("Description (shown to people deciding whether to run it)", spec.description, textCheck("description")); err != nil {
		return err
	}
	if spec.authors, err = p.askList("Authors (comma-separated)", spec.authors, textCheck("author")); err != nil {
		return err
	}
	if spec.base, err = p.choose("Base agent:", manifest.BaseAgents, spec.base); err != nil {
		return err
	}
	if !versionFromFlag {
		spec.baseVersion = baseVersionFor(spec.base)
	}
	if spec.baseVersion, err = p.ask("Base agent version (kit tag)", spec.baseVersion, checkBaseVersion); err != nil {
		return err
	}
	fmt.Fprintln(out, "\nPermissions are denied unless you list them.")
	if spec.egress, err = p.askList("Egress hosts the agent may contact (comma-separated, \"none\" for none)", spec.egress, func(h string) error {
		if !manifest.ValidHost(h) {
			return fmt.Errorf("%q is not a valid host: use an exact lowercase hostname, no wildcard, scheme, port or IP address", shown(h))
		}
		return nil
	}); err != nil {
		return err
	}
	for {
		path, err := p.ask("Mount path inside the workspace (blank to finish)", "", func(s string) error {
			if s != "" && !manifest.ValidMountPath(s) {
				return errors.New("must be a relative path inside the workspace (no leading '/', no '..')")
			}
			return nil
		})
		if err != nil {
			return err
		}
		if path == "" {
			break
		}
		mode, err := p.choose("Mode:", []string{"read-only", "read-write"}, "read-only")
		if err != nil {
			return err
		}
		if mode == "read-write" {
			fmt.Fprintf(out, "  warning: read-write lets the agent create, change and delete files under %s\n", shown(path))
		}
		spec.mounts = append(spec.mounts, manifest.Mount{Path: path, Mode: mode})
	}
	secrets, err := p.askList("Secret names the agent needs (comma-separated, UPPER_SNAKE_CASE)", spec.secrets, func(s string) error {
		if !manifest.ValidSecretName(s) {
			return fmt.Errorf("%q must start with a capital letter and use only capitals, digits and '_'", shown(s))
		}
		return nil
	})
	if err != nil {
		return err
	}
	spec.secrets = secrets
	for {
		name, err := p.ask("MCP server name (blank to finish)", "", func(s string) error {
			if s == "" {
				return nil
			}
			if !manifest.ValidName(s) {
				return errors.New("use lowercase letters, digits and '-'")
			}
			for _, m := range spec.mcp {
				if m.Name == s {
					return errors.New("already added")
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if name == "" {
			break
		}
		url, err := p.ask("  URL (https)", "", func(s string) error {
			if _, err := manifest.MCPHost(s); err != nil {
				return fmt.Errorf("URL %v", err)
			}
			return nil
		})
		if err != nil {
			return err
		}
		secret := ""
		if len(spec.secrets) > 0 {
			if secret, err = p.ask("  Secret sent to it (one of: "+strings.Join(spec.secrets, ", ")+"; blank for none)", "", func(s string) error {
				if s != "" && !contains(spec.secrets, s) {
					return errors.New("not one of the declared secrets")
				}
				return nil
			}); err != nil {
				return err
			}
		}
		spec.mcp = append(spec.mcp, manifest.MCP{Name: name, URL: url, Secret: secret})
	}
	if spec.prompt, err = p.yesNo("Create a starter prompt file ("+starterPromptPath+")?", true); err != nil {
		return err
	}
	// Optional, and last so that answers scripted before it existed still
	// line up: input that ends here just skips it.
	spec.repository, err = p.ask("Repository URL (https://github.com/<owner>/<repo>; blank for none)", spec.repository, func(s string) error {
		if s == "" {
			return nil
		}
		if _, _, ok := manifest.ParseRepository(s); !ok {
			return errors.New("must be https://github.com/<owner>/<repo> exactly (no trailing slash, .git, query or fragment)")
		}
		return nil
	})
	if errors.Is(err, errInputEnded) {
		return nil
	}
	return err
}

// --- output ----------------------------------------------------------------

// q quotes a user-supplied scalar as a YAML double-quoted string.
func q(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSpace(b.String())
}

func qList(items []string) string {
	qs := make([]string, len(items))
	for i, s := range items {
		qs[i] = q(s)
	}
	return "[" + strings.Join(qs, ", ") + "]"
}

// renderManifest writes capm.yaml from a template so the comments survive.
// Empty optional sections are written as empty lists, the most restrictive
// choice.
func renderManifest(s initSpec) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("# capm bundle manifest. Run `capm lint` to check it and `capm inspect .` to see what it declares.\n")
	w("apiVersion: capm/v0\nkind: Agent\n\n")
	w("# Identity: this bundle is published as <your login>/%s@<version>; bump the version for every push.\n", s.name)
	w("metadata:\n  name: %s\n  version: 0.1.0\n", s.name)
	if s.description != "" {
		w("  description: %s\n", q(s.description))
	} else {
		w("  # description: say what this bundle does, in one line\n")
	}
	if len(s.authors) > 0 {
		w("  authors: %s\n", qList(s.authors))
	} else {
		w("  # authors: [your-github-login]\n")
	}
	if s.repository != "" {
		w("  # Where the source lives. The registry marks it verified only when the bundle is published from a GitHub Actions workflow of this repository.\n")
		w("  repository: %s\n", q(s.repository))
	} else {
		w("  # repository: https://github.com/<owner>/<repo>\n")
	}
	w("\n# The agent runtime this bundle runs on, and its kit tag. Supported: %s.\n", strings.Join(manifest.BaseAgents, ", "))
	w("base:\n  agent: %s\n  version: %s\n\n", s.base, q(s.baseVersion))
	w("# How people talk to the agent. Only \"tty\" (a terminal) is supported.\ninterface:\n  type: tty\n\n")
	w("# The model API the bundle expects; whoever runs it supplies the endpoint and key.\n")
	w("model:\n  api: openai-compatible\n  requires:\n    toolCalling: true\n    minContextTokens: 32000\n\n")
	w("# What the agent may reach. Everything is denied unless it is listed here.\npermissions:\n")
	w("  # Hosts the agent may contact: exact lowercase hostnames, no wildcards.\n")
	if len(s.egress) == 0 {
		w("  egress: []\n")
	} else {
		w("  egress:\n")
		for _, h := range s.egress {
			w("    - %s\n", q(h))
		}
	}
	w("  # Workspace paths mounted into the sandbox. read-write lets the agent change files there.\n")
	if len(s.mounts) == 0 {
		w("  mounts: []\n")
	} else {
		w("  mounts:\n")
		for _, m := range s.mounts {
			w("    - path: %s\n      mode: %s\n", q(m.Path), m.Mode)
		}
	}
	w("\n# Names of secrets the agent needs (never values); the person running it supplies them.\n")
	if len(s.secrets) == 0 {
		w("secrets: []\n")
	} else {
		w("secrets:\n")
		for _, n := range s.secrets {
			w("  - name: %s\n", n)
		}
	}
	w("\n# MCP servers the agent connects to (https only). A secret, if set, is sent only to that server.\n")
	if len(s.mcp) == 0 {
		w("mcp: []\n")
	} else {
		w("mcp:\n")
		for _, m := range s.mcp {
			w("  - name: %s\n    url: %s\n", m.Name, q(m.URL))
			if m.Secret != "" {
				w("    secret: %s\n", m.Secret)
			}
		}
	}
	w("\n# Files published with the bundle and given to the agent as context. Only files listed here\n")
	w("# (plus capm.yaml and a root README.md) are published; everything else in this directory stays local.\n")
	if s.prompt {
		w("context:\n  - %s\n", starterPromptPath)
	} else {
		w("context: []\n")
	}
	return b.String()
}

// writeBundle creates dir (0755) and writes capm.yaml and, when wanted, the
// starter prompt (0644), never replacing an existing file. It returns what it
// created, as paths under dir.
func writeBundle(dir, manifestText string, withPrompt bool) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var created []string
	create := func(rel, content string) error {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			if rel == manifest.FileName {
				return fmt.Errorf("%s already exists", p)
			}
			created = append(created, p+" (already existed, left as is)")
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := io.WriteString(f, content); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		created = append(created, p)
		return nil
	}
	if err := create(manifest.FileName, manifestText); err != nil {
		return created, err
	}
	if withPrompt {
		if err := create(starterPromptPath, starterPrompt); err != nil {
			return created, err
		}
	}
	return created, nil
}
