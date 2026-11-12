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
	registry string                 // registry base URL
	credDir  string                 // directory holding credentials.json
	sleep    func(time.Duration)    // used while polling for login
	now      func() time.Time       // nil means time.Now (token expiry warning)
	hostname func() (string, error) // nil means os.Hostname (names the login token)

	// capm run; nil fields get real defaults (see runDefaults).
	ctx        context.Context
	stdin      io.Reader
	isTTY      func() bool
	getenv     func(string) string
	readSecret func(prompt string) (string, error) // no-echo prompt
	runner     sbx.Runner
	tempRoot   string // parent for temp dirs; "" means os.TempDir()
}

// version is set at build time with -ldflags "-X main.version=<commit>".
var version = "dev"

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
  whoami    Print the login you are authenticated as
  logout    Revoke this machine's token and delete the stored credentials
  tokens    List your login tokens; "tokens revoke <id>" revokes one
  usage     Show your storage use and the registry's limits
  init      Create a commented capm.yaml (and a starter prompt) in a new bundle directory
  lint      Check a bundle directory for problems before publishing; "--strict" makes warnings fail
  push      Package and publish an agent to a registry
  pull      Download a bundle and check it against the registry's sha256 digest (bundles are not signed)
  inspect   Show the bundle's declared permissions (not enforced; see the egress line);
            with --diff [oldversion], show what changed since the version you last ran
  run       Launch an agent in a Docker Sandbox (sbx)
  search    Find bundles whose owner, name or description contains the text
  list      List bundles in the registry, or only one owner's
  known     List the bundles capm remembers (pinned owners); known forget <owner/name>
  version   Print the capm version

capm run [--yes] [--workdir DIR] [--model-url URL] [--model-key KEY] [--model NAME]
         [--allow-unenforced-egress] [--allow-global-anthropic-secret] [--accept-new-owner]
         [--accept-permission-changes] [--accept-changed-digest] <dir | user/name[@version]>
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
  For a registry bundle, capm remembers the owner's account id the first time
  and refuses if it later changes unless --accept-new-owner is given.
  It also remembers the permissions of the last registry version you ran and,
  before asking to confirm a different version, shows what changed (+ added,
  - removed, ~ changed). When something is added or widened, --yes alone does
  not skip the confirmation: non-interactive runs need --accept-permission-changes.
  The same version served with different bytes is refused unless
  --accept-changed-digest is given.

capm init [dir] [--yes] [--name N] [--description T] [--author A] [--base AGENT] [--base-version TAG]
          [--egress HOST] [--mount PATH[:MODE]] [--secret NAME]
  Writes a commented capm.yaml (version 0.1.0, no egress, mounts, secrets or MCP
  servers unless you ask) and optionally prompts/system.md. Asks questions on a
  terminal; --yes takes the defaults plus any flags. Never overwrites a file.

capm lint [dir] [--strict] [--offline]
  Checks the bundle: manifest errors, missing context files, credential-looking
  files (errors; push refuses on these too, see --allow-secret-files), unlisted
  files (not published), size, and whether the version is new on the registry
  (skipped with --offline). Exit 0 ok, 1 errors (or warnings with --strict), 2 usage.

capm push [--allow-secret-files] <dir>
  Refuses before any request when a listed context file is missing or a packed
  file looks like a credential.

capm pull [--accept-new-owner] user/name[@version]
  Downloads the bundle into ./name/ after checking its digest, and remembers
  the owner's account id the same way. --accept-new-owner accepts a changed owner.

capm list [owner] [--sort name|recent|downloads] / capm search <text> [--sort name|recent|downloads]
  --sort recent orders by the newest version's date and adds a YYYY-MM-DD
  column; --sort downloads orders by raw download requests over the last 30
  days and adds that count as a column. Counts can be inflated by anyone and
  are not a trust or quality signal. name (the default) is alphabetical. A
  registry that does not support sorting is noted once on stderr and shown
  in its default order.
  A "!!" or "!" before the description is the registry's claim about the
  bundle's highest risk label (!! high, ! caution); blank means none flagged,
  an info-only label, or a registry that does not report it, and is not an
  endorsement. capm inspect and capm run compute the risk labels locally from
  the manifest and do not use the registry's claim.
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
	case "admin":
		return admin(args[1:], stdout, stderr, e)
	case "inspect":
		return inspect(args[1:], stdout, stderr, e)
	case "lint":
		return lint(args[1:], stdout, stderr, e)
	case "init":
		return initCmd(args[1:], stdout, stderr, e)
	case "login":
		return login(args[1:], stdout, stderr, e)
	case "whoami":
		return whoami(args[1:], stdout, stderr, e)
	case "logout":
		return logout(args[1:], stdout, stderr, e)
	case "tokens":
		return tokens(args[1:], stdout, stderr, e)
	case "usage":
		return usageCmd(args[1:], stdout, stderr, e)
	case "push":
		return push(args[1:], stdout, stderr, e)
	case "pull":
		return pull(args[1:], stdout, stderr, e)
	case "run":
		return runCmd(args[1:], stdout, stderr, e)
	case "search":
		return search(args[1:], stdout, stderr, e)
	case "list":
		return list(args[1:], stdout, stderr, e)
	case "known":
		return knownCmd(args[1:], stdout, stderr, e)
	case "version":
		fmt.Fprintf(stdout, "capm %s\n", version)
		return 0
	default:
		fmt.Fprintf(stderr, "capm: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
