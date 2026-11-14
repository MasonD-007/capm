package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// Owner pinning: the first time this machine runs or pulls registry+owner/name
// it remembers the owner's numeric account id. A later, different id means the
// name now belongs to another account (a login can be released and re-registered),
// and the CLI refuses unless told to accept the new owner.

type pinState int

const (
	pinNew         pinState = iota // nothing pinned yet
	pinMatch                       // the pinned id equals the registry's
	pinChanged                     // the registry reports a different id
	pinUnavailable                 // the registry sent no id (older server)
)

type pinInfo struct {
	state           pinState
	pinned, current int64
}

func pinStatus(rec knownRecord, recorded bool, ownerID int64) pinInfo {
	info := pinInfo{state: pinNew, current: ownerID}
	if recorded {
		info.pinned = rec.OwnerID
	}
	switch {
	case ownerID <= 0:
		info.state = pinUnavailable
	case info.pinned == 0:
		info.state = pinNew
	case info.pinned == ownerID:
		info.state = pinMatch
	default:
		info.state = pinChanged
	}
	return info
}

// newOwnerRefusal is the message printed (after "capm <cmd>: ") when the
// registry's owner id differs from the pinned one.
func newOwnerRefusal(owner, name string, info pinInfo) string {
	return fmt.Sprintf("refusing %s/%s: its owner changed.\n"+
		"  pinned owner id (from when you first ran or pulled it): %d\n"+
		"  owner id the registry reports now:                      %d\n"+
		"The name may have been taken over by a different GitHub account. "+
		"If you trust the new owner, run again with --accept-new-owner to proceed and pin the new id.",
		owner, name, info.pinned, info.current)
}

// gateOwner applies pinning for a command that fetched owner/name. It returns
// false (after printing why) when the command must stop. It never writes; the
// caller records the pin with recordPin once it is about to use the bundle.
func (k *knownStore) gateOwner(cmd string, stderr io.Writer, registry, owner, name string, ownerID int64, accept bool) (pinInfo, bool) {
	rec, ok := k.get(registry, owner, name)
	info := pinStatus(rec, ok, ownerID)
	switch info.state {
	case pinUnavailable:
		fmt.Fprintf(stderr, "warning: the registry did not report an owner id for %s/%s, so owner pinning is unavailable for this registry; continuing without it\n", owner, name)
	case pinChanged:
		if !accept {
			fmt.Fprintf(stderr, "capm %s: %s\n", cmd, newOwnerRefusal(owner, name, info))
			return info, false
		}
		fmt.Fprintf(stderr, "warning: accepting new owner id %d for %s/%s (was %d)\n", info.current, owner, name, info.pinned)
	}
	return info, true
}

// setPin applies a pin decision to r.
func setPin(r *knownRecord, info pinInfo) {
	if (info.state == pinNew || info.state == pinChanged) && info.current > 0 {
		r.OwnerID = info.current
		r.PinnedAt = time.Now().UTC()
	}
}

// describePin is the line `capm inspect` prints about pinning; it never writes.
func describePin(info pinInfo, rec knownRecord, recorded bool) string {
	switch info.state {
	case pinMatch:
		return fmt.Sprintf("pin: owner id %d matches the owner you pinned", info.current)
	case pinChanged:
		return fmt.Sprintf("pin: WARNING owner id is %d but you pinned %d; this name may have been taken over by a different GitHub account (run/pull will refuse without --accept-new-owner)", info.current, info.pinned)
	case pinUnavailable:
		if recorded && rec.OwnerID > 0 {
			return fmt.Sprintf("pin: the registry reported no owner id (you pinned %d); pinning is unavailable for this registry", rec.OwnerID)
		}
		return "pin: the registry reported no owner id; owner pinning is unavailable for this registry"
	default:
		return fmt.Sprintf("pin: not pinned yet (owner id %d); it will be pinned the first time you run or pull it", info.current)
	}
}

const knownUse = "usage: capm known [forget <owner/name>]"

// knownCmd implements `capm known`: list what capm remembers, or forget one.
func knownCmd(args []string, stdout, stderr io.Writer, e env) int {
	ks := newKnownStore(e, stderr)
	switch {
	case len(args) == 0:
		entries := ks.all()
		if len(entries) == 0 {
			fmt.Fprintln(stdout, "capm has no remembered bundles")
			return 0
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "REGISTRY\tBUNDLE\tOWNER ID\tLAST RUN\tPINNED\tSIGNER")
		for _, en := range entries {
			last, pinned := "-", "-"
			if en.Record.LastRun != nil {
				last = client.Sanitize(en.Record.LastRun.Version)
			}
			id := "-"
			if en.Record.OwnerID > 0 {
				id = fmt.Sprint(en.Record.OwnerID)
				if !en.Record.PinnedAt.IsZero() {
					pinned = en.Record.PinnedAt.Format("2006-01-02")
				}
			}
			signer := "-"
			if p := en.Record.SignerPin; p != nil && p.Repository != "" {
				// Everything here came from a verified certificate.
				signer = fmt.Sprintf("%s (verified %s)", client.Sanitize(p.Repository), client.Sanitize(p.VerifiedVersion))
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", client.Sanitize(en.Registry), client.Sanitize(en.Key), id, last, pinned, signer)
		}
		tw.Flush()
		return 0
	case args[0] == "forget" && len(args) == 2:
		owner, name, found := strings.Cut(args[1], "/")
		if !found || owner == "" || name == "" || strings.Contains(name, "/") {
			fmt.Fprintf(stderr, "capm known: invalid bundle %q (want owner/name)\n%s\n", client.Sanitize(args[1]), knownUse)
			return 2
		}
		ok, err := ks.forget(e.registry, owner, name)
		if err != nil {
			fmt.Fprintf(stderr, "capm known: %v\n", err)
			return 1
		}
		if !ok {
			fmt.Fprintf(stderr, "capm known: nothing remembered for %s/%s on %s\n", client.Sanitize(owner), client.Sanitize(name), client.Sanitize(e.registry))
			return 1
		}
		fmt.Fprintf(stdout, "forgot %s/%s on %s\n", client.Sanitize(owner), client.Sanitize(name), client.Sanitize(e.registry))
		return 0
	}
	fmt.Fprintln(stderr, knownUse)
	return 2
}
