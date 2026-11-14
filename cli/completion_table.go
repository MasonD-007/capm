package main

import "github.com/MasonD-007/capm/manifest"

// The command table is the single description of the CLI's surface that the
// shell completion scripts (completion_gen.go) are generated from. It is kept
// in step with the dispatch code by TestCompletionTableMatchesDispatch, which
// parses cli/run.go and the other dispatching functions with go/parser, so a
// command or subcommand added to the code but not to this table fails CI.
// TestCompletionTableFlagsMatchFlagSets does the same for the flags of every
// command that builds a flag.FlagSet (init, run, lint, push); the flags that
// other commands parse by hand are only as accurate as this table.

// valueKind says what a flag takes after it.
type valueKind int

const (
	valNone valueKind = iota // boolean flag
	valFree                  // free text; nothing is completed
	valEnum                  // one of flagSpec.Enum
	valDir                   // a directory (the shell's own completion)
	valFile                  // a path (the shell's own completion)
)

// posKind says what the positional argument of a command (or subcommand) is.
type posKind int

const (
	posNone        posKind = iota // takes none; nothing is completed
	posBundle                     // owner/name[@version], completed from the registry
	posDir                        // a bundle directory (the shell's own completion)
	posDirOrBundle                // a directory or owner/name[@version]
	posOwner                      // an owner login (free text)
	posTokenID                    // a login token id (free text)
	posFree                       // free text
	posUser                       // a login or numeric id (free text)
	posID                         // a numeric id (free text)
	posShell                      // bash, zsh or fish
)

type flagSpec struct {
	Name  string // without the leading dashes
	Short string // optional one-letter alias, without the dash
	Value valueKind
	Enum  []string
}

type cmdSpec struct {
	Name   string
	Desc   string
	Hidden bool // completed only once its parent has been typed (admin)
	Flags  []flagSpec
	Pos    posKind
	Subs   []cmdSpec // a command with subcommands completes them at its position
}

// completionShells are the shells `capm completion` knows.
var completionShells = []string{"bash", "zsh", "fish"}

var (
	sortValues   = []string{"name", "recent", "downloads"}
	reasonValues = []string{"malware", "secrets-exposed", "impersonation", "other"}
)

func boolFlag(name string) flagSpec { return flagSpec{Name: name} }
func freeFlag(name string) flagSpec { return flagSpec{Name: name, Value: valFree} }

// commandTable lists every command in the order of the usage text.
var commandTable = []cmdSpec{
	{Name: "login", Desc: "Authenticate with a registry", Flags: []flagSpec{boolFlag("orgs"), boolFlag("oidc"), freeFlag("audience")}},
	{Name: "whoami", Desc: "Print the login you are authenticated as"},
	{Name: "orgs", Desc: "List the organisations you may publish under"},
	{Name: "logout", Desc: "Revoke this machine's token and delete the stored credentials"},
	{Name: "tokens", Desc: "List your login tokens; revoke one by id", Subs: []cmdSpec{
		{Name: "revoke", Desc: "Revoke a login token", Pos: posTokenID},
	}},
	{Name: "usage", Desc: "Show your storage use and the registry's limits", Flags: []flagSpec{freeFlag("owner")}},
	{Name: "init", Desc: "Create a commented capm.yaml in a bundle directory", Pos: posDir, Flags: []flagSpec{
		{Name: "yes", Short: "y"}, freeFlag("name"), freeFlag("description"), freeFlag("author"),
		{Name: "base", Value: valEnum, Enum: manifest.BaseAgents}, freeFlag("base-version"),
		freeFlag("egress"), {Name: "mount", Value: valFile}, freeFlag("secret"), freeFlag("repository"),
	}},
	{Name: "lint", Desc: "Check a bundle directory for problems before publishing", Pos: posDir,
		Flags: []flagSpec{boolFlag("strict"), boolFlag("offline"), freeFlag("owner")}},
	{Name: "push", Desc: "Package and publish an agent to a registry", Pos: posDir,
		Flags: []flagSpec{boolFlag("allow-secret-files"), freeFlag("owner")}},
	{Name: "pull", Desc: "Download a bundle and check its digest", Pos: posBundle,
		Flags: []flagSpec{boolFlag("accept-new-owner"), boolFlag("accept-new-signer"), boolFlag("allow-invalid-signature")}},
	{Name: "inspect", Desc: "Show a bundle's declared permissions", Pos: posDirOrBundle,
		Flags: []flagSpec{boolFlag("diff")}},
	{Name: "run", Desc: "Launch an agent in a Docker Sandbox (sbx)", Pos: posDirOrBundle, Flags: []flagSpec{
		{Name: "yes", Short: "y"}, boolFlag("allow-unenforced-egress"), boolFlag("allow-global-anthropic-secret"),
		boolFlag("accept-new-owner"), boolFlag("accept-new-signer"), boolFlag("allow-invalid-signature"),
		boolFlag("accept-permission-changes"), boolFlag("accept-changed-digest"),
		{Name: "workdir", Value: valDir}, freeFlag("model-url"), freeFlag("model-key"), freeFlag("model"),
	}},
	{Name: "search", Desc: "Find bundles whose owner, name or description contains the text", Pos: posFree,
		Flags: []flagSpec{{Name: "sort", Value: valEnum, Enum: sortValues}}},
	{Name: "list", Desc: "List bundles in the registry, or only one owner's", Pos: posOwner,
		Flags: []flagSpec{{Name: "sort", Value: valEnum, Enum: sortValues}}},
	{Name: "report", Desc: "Report a bundle to the registry operator", Pos: posBundle, Flags: []flagSpec{
		{Name: "reason", Value: valEnum, Enum: reasonValues}, freeFlag("details"),
	}},
	{Name: "known", Desc: "List the bundles capm remembers; forget one", Subs: []cmdSpec{
		{Name: "forget", Desc: "Forget a remembered bundle", Pos: posBundle},
	}},
	{Name: "self-update", Desc: "Replace this binary with the latest release", Flags: []flagSpec{boolFlag("check")}},
	{Name: "outdated", Desc: "List bundles you have run that have a newer version"},
	{Name: "completion", Desc: "Print a shell completion script (bash, zsh or fish)", Pos: posShell},
	{Name: "version", Desc: "Print the capm version"},
	{Name: "admin", Desc: "Registry administration (admins only)", Hidden: true, Subs: []cmdSpec{
		{Name: "remove", Desc: "Take down a version or a whole bundle", Pos: posBundle, Flags: []flagSpec{freeFlag("reason")}},
		{Name: "restore", Desc: "Undo a removal", Pos: posBundle},
		{Name: "ban", Desc: "Block a user and hide their bundles", Pos: posUser, Flags: []flagSpec{freeFlag("reason")}},
		{Name: "unban", Desc: "Lift a ban", Pos: posUser},
		{Name: "revoke-tokens", Desc: "Revoke every login token of a user", Pos: posUser},
		{Name: "quota", Desc: "Show or set a user's storage limits", Pos: posUser,
			Flags: []flagSpec{freeFlag("bytes"), freeFlag("bundles"), boolFlag("reset")}},
		{Name: "log", Desc: "Show the audit log of admin actions"},
		{Name: "reports", Desc: "List abuse reports", Flags: []flagSpec{boolFlag("all"), boolFlag("resolved")}},
		{Name: "report", Desc: "Show one report in full", Pos: posID},
		{Name: "resolve", Desc: "Mark a report handled", Pos: posID, Flags: []flagSpec{freeFlag("note")}},
	}},
}

// hiddenCommands are dispatched but never completed: __complete is the
// callback the scripts use, and help is spelled out in usage.
var hiddenCommands = map[string]bool{"__complete": true, "help": true, "-h": true, "--help": true}
