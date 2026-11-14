package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
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

	upd updateEnv // self-update and the update notice (updatecheck.go)

	// verify replaces sigverify.Verify. Only unit tests set it; nil means the
	// real verifier, and there is no way to set it from the command line or
	// environment (see sigcheck.go).
	verify verifyFunc

	// actionsHosts, when set, replaces the GitHub Actions host check of
	// `capm login --oidc`. Only unit tests set it; there is no way to set it
	// from the command line or environment (see testActionsHosts).
	actionsHosts func(*url.URL) bool
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
  orgs      List the organisations you may publish under (recorded by login --orgs)
  logout    Revoke this machine's token and delete the stored credentials
  tokens    List your login tokens; "tokens revoke <id>" revokes one
  usage     Show your storage use and the registry's limits
  init      Create a commented capm.yaml (and a starter prompt) in a new bundle directory
  lint      Check a bundle directory for problems before publishing; "--strict" makes warnings fail
  push      Package and publish an agent to a registry
  pull      Download a bundle, check its sha256 digest and, when it is signed, its signer
  inspect   Show the bundle's declared permissions (not enforced; see the egress line);
            with --diff [oldversion], show what changed since the version you last ran
  run       Launch an agent in a Docker Sandbox (sbx)
  search    Find bundles whose owner, name or description contains the text
  list      List bundles in the registry, or only one owner's
  report    Report a bundle to the registry operator (malware, exposed secrets, impersonation)
  known     List the bundles capm remembers (pinned owners); known forget <owner/name>
  self-update  Replace this binary with the latest release (--check only reports)
  outdated  List bundles you have run that have a newer version, and what it changes
  completion  Print a shell completion script (bash, zsh or fish)
  version   Print the capm version

capm run [--yes] [--workdir DIR] [--model-url URL] [--model-key KEY] [--model NAME]
         [--allow-unenforced-egress] [--allow-global-anthropic-secret] [--accept-new-owner]
         [--accept-new-signer]
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
  A registry bundle's signer is checked before the plan is shown. Most bundles
  are not signed; that is said plainly and allowed. A bundle that claims to be
  signed but cannot be checked is refused (--yes does not override that, and the
  refusal names the one flag that does). Which repository signs a bundle is
  pinned like its owner; a different one is refused unless --accept-new-signer
  is given. See docs/security-notes.md.

capm report <user/name[@version]> --reason malware|secrets-exposed|impersonation|other [--details TEXT]
  Sends an abuse report to the registry operator, who reviews it by hand. It
  works without logging in (a stored login only records who reported). A report
  removes nothing by itself. Limited to a few reports per hour per network.

capm init [dir] [--yes] [--name N] [--description T] [--author A] [--base AGENT] [--base-version TAG]
          [--egress HOST] [--mount PATH[:MODE]] [--secret NAME] [--repository URL]
  Writes a commented capm.yaml (version 0.1.0, no egress, mounts, secrets or MCP
  servers unless you ask) and optionally prompts/system.md. Asks questions on a
  terminal; --yes takes the defaults plus any flags. Never overwrites a file.

capm lint [dir] [--strict] [--offline] [--owner <org>]
  Checks the bundle: manifest errors, missing context files, credential-looking
  files (errors; push refuses on these too, see --allow-secret-files), unlisted
  files (not published), size, and whether the version is new on the registry
  (skipped with --offline). Exit 0 ok, 1 errors (or warnings with --strict), 2 usage.

capm push [--owner <org>] [--allow-secret-files] <dir>
  Refuses before any request when a listed context file is missing or a packed
  file looks like a credential. Publishes under your login unless --owner (or
  CAPM_OWNER) names a GitHub organisation; the registry decides whether you may
  and prints its refusal. capm lint and capm usage accept --owner too.

capm login --orgs
  Also asks GitHub for read:org so the registry can record which organisations
  you may publish under (owners, and members of organisations whose base
  permission is write). The record lasts 24 hours; run it again to refresh it.
  Plain capm login asks GitHub for no extra permission. capm orgs lists the record.

CI: CAPM_TOKEN=<token> makes every command that signs in use that token for the
  current registry instead of the stored login (it is never written to disk, and
  capm logout leaves the stored login alone). A publish-only CI token cannot say
  who it belongs to, so also set CAPM_OWNER=<github login> for push and lint.
capm login --oidc [--audience URL]
  Inside GitHub Actions (permissions: id-token: write) trades the job's identity
  for a 15-minute publish-only token and prints just that token to stdout, e.g.
  CAPM_TOKEN=$(capm login --oidc). Nothing is stored. The audience defaults to
  the registry URL.

capm pull [--accept-new-owner] [--accept-new-signer] user/name[@version]
  Downloads the bundle into ./name/ after checking its digest, and remembers
  the owner's account id the same way. --accept-new-owner accepts a changed owner.
  It also checks who signed the bundle, when it is signed, and says on one
  line what was and was not proven; --accept-new-signer is as for
  capm run. capm inspect prints the same kind of line for a registry bundle but
  does not download it, so it can only say the signer matches the digest the
  registry reports.

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
	code := runCommand(args, stdout, stderr, e)
	// Once a day, after a command has succeeded: see updatecheck.go.
	e.maybeNotifyUpdate(args, code, stderr)
	return code
}

func runCommand(args []string, stdout, stderr io.Writer, e env) int {
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
	case "orgs":
		return orgsCmd(args[1:], stdout, stderr, e)
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
	case "report":
		return reportCmd(args[1:], stdout, stderr, e)
	case "known":
		return knownCmd(args[1:], stdout, stderr, e)
	case "self-update":
		return selfUpdate(args[1:], stdout, stderr, e)
	case "outdated":
		return outdated(args[1:], stdout, stderr, e)
	case "completion":
		return completion(args[1:], stdout, stderr, e)
	case "__complete": // hidden: the shell completion scripts call it (cmd_complete.go)
		return completeCmd(args[1:], stdout, e)
	case "version":
		fmt.Fprintf(stdout, "capm %s\n", version)
		return 0
	default:
		fmt.Fprintf(stderr, "capm: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
