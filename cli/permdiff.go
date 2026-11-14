package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/manifest"
)

// Permission diff on upgrade: `capm run` remembers the version, digest and
// manifest of the last run it was authorised to start, and shows what changed
// the next time a different version (or different bytes) is about to run.

// sinceLastRun is what a registry run learned from the recorded previous run.
type sinceLastRun struct {
	has      bool
	from, to string // versions
	diff     manifest.PermissionDiff
}

func (s sinceLastRun) escalates() bool { return s.has && s.diff.Escalates() }

// render is the section printed before the confirmation; "" if there is no
// previous run to compare with.
func (s sinceLastRun) render() string {
	if !s.has {
		return ""
	}
	head := fmt.Sprintf("Changes since the version you last ran (%s -> %s)", client.Sanitize(s.from), client.Sanitize(s.to))
	if s.diff.Empty() {
		return head + ": no permission changes\n\n"
	}
	return head + "\n" + s.diff.Render() + "\n"
}

// changedDigestRefusal is printed (after "capm run: ") when the registry serves
// other bytes for a version that was recorded with a different digest.
func changedDigestRefusal(owner, name string, lr *lastRun, now string) string {
	return fmt.Sprintf("refusing %s/%s@%s: the registry now serves different bytes for this version than when you last ran it\n"+
		"  recorded digest: %s\n"+
		"  digest now:      %s\n"+
		"A published version should never change. If you trust the registry and the owner, run again with --accept-changed-digest.",
		owner, name, lr.Version, client.Sanitize(lr.Digest), client.Sanitize(now))
}

// escalationRefusal is printed (after "capm run: ") when permissions were added
// or widened and the run cannot be confirmed interactively.
func escalationRefusal(s sinceLastRun, yes bool) string {
	flags := "--accept-permission-changes"
	if !yes {
		flags = "--yes and --accept-permission-changes"
	}
	return fmt.Sprintf("permissions were added or widened since the version you last ran (%s -> %s), so --yes alone does not approve the run; "+
		"pass %s to run non-interactively, or run capm in a terminal to confirm",
		client.Sanitize(s.from), client.Sanitize(s.to), flags)
}

// compareLastRun compares the fetched bundle with the recorded last run. ok is
// false (after printing why) when a same-version/different-bytes change must
// stop the run.
func (k *knownStore) compareLastRun(stderr io.Writer, registry, owner, name string, res client.Resolved, m *manifest.Manifest, acceptDigest bool) (sinceLastRun, bool) {
	rec, found := k.get(registry, owner, name)
	if !found || rec.LastRun == nil {
		return sinceLastRun{}, true
	}
	lr := rec.LastRun
	sameVersion := lr.Version == res.Version
	if sameVersion && lr.Digest == res.Digest {
		return sinceLastRun{}, true
	}
	if sameVersion {
		if !acceptDigest {
			fmt.Fprintf(stderr, "capm run: %s\n", changedDigestRefusal(owner, name, lr, res.Digest))
			return sinceLastRun{}, false
		}
		fmt.Fprintf(stderr, "warning: %s/%s@%s changed since you last ran it; continuing because of --accept-changed-digest\n", owner, name, res.Version)
	}
	if lr.Manifest == nil {
		return sinceLastRun{}, true
	}
	return sinceLastRun{has: true, from: lr.Version, to: res.Version, diff: manifest.DiffPermissions(lr.Manifest, m)}, true
}

// recordRun stores the owner pin and the run just authorised.
func (k *knownStore) recordRun(stderr io.Writer, registry, owner, name string, pin pinInfo, sig sigOutcome, res client.Resolved, m *manifest.Manifest) {
	err := k.update(registry, owner, name, func(r *knownRecord) {
		setPin(r, pin)
		sig.record(r, res.Version)
		r.LastRun = &lastRun{Version: res.Version, Digest: res.Digest, Manifest: m, At: time.Now().UTC()}
	})
	if err != nil {
		fmt.Fprintf(stderr, "warning: could not save %s: %v\n", knownFileName, err)
	}
}

// parseInspectArgs handles `<target> [--diff [oldversion]]`. oldversion is
// taken only after the target (so `--diff alice/x` still reads alice/x as the
// target) and only when it does not look like a flag.
func parseInspectArgs(args []string) (target string, diff bool, old string, ok bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--diff":
			diff = true
			if target != "" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				old = args[i]
			}
		case strings.HasPrefix(a, "--diff="):
			diff, old = true, strings.TrimPrefix(a, "--diff=")
		case target == "":
			target = a
		default:
			return "", false, "", false
		}
	}
	return target, diff, old, target != ""
}

// inspectDiff prints the permission diff for owner/name@res.Version against
// the recorded last run, or against oldVersion fetched from the registry. It
// never writes.
func inspectDiff(c *client.Client, ks *knownStore, e env, owner, name string, res client.Resolved, md client.Metadata, oldVersion string, stdout, stderr io.Writer) int {
	var (
		old     *manifest.Manifest
		oldFrom string
		oldDig  string
	)
	if oldVersion != "" {
		omd, err := c.Metadata(owner, name, oldVersion)
		if err != nil {
			failFetch(stderr, "inspect", err)
			return 1
		}
		om := &omd.Manifest
		if err := om.Validate(); err != nil {
			fmt.Fprintf(stderr, "capm inspect: registry returned an invalid manifest for %s:\n%s\n", client.Sanitize(oldVersion), manifest.DisplaySafe(err.Error()))
			return 1
		}
		if omd.Version != oldVersion || om.Metadata.Version != oldVersion {
			fmt.Fprintf(stderr, "capm inspect: registry metadata does not match %s/%s@%s\n", owner, name, client.Sanitize(oldVersion))
			return 1
		}
		old, oldFrom = om, oldVersion
	} else {
		rec, found := ks.get(e.registry, owner, name)
		if !found || rec.LastRun == nil || rec.LastRun.Manifest == nil {
			fmt.Fprintf(stdout, "nothing recorded for %s/%s: you have not run it on this machine. Pass an old version to compare against: capm inspect %s/%s@%s --diff <oldversion>\n",
				owner, name, owner, name, res.Version)
			return 0
		}
		old, oldFrom, oldDig = rec.LastRun.Manifest, rec.LastRun.Version, rec.LastRun.Digest
	}
	s := sinceLastRun{has: true, from: oldFrom, to: res.Version, diff: manifest.DiffPermissions(old, &md.Manifest)}
	if oldVersion == "" {
		fmt.Fprintln(stdout, "comparing with the version you last ran")
		if oldFrom == res.Version && oldDig != "" && oldDig != md.Digest {
			fmt.Fprintf(stdout, "WARNING: the registry's digest for %s differs from the one recorded when you ran it\n", client.Sanitize(res.Version))
		}
	}
	text := s.render()
	if oldVersion != "" {
		text = strings.Replace(text, "Changes since the version you last ran", "Changes", 1)
	}
	fmt.Fprint(stdout, text)
	return 0
}
