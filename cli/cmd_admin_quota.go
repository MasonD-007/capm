package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// quotaArgs parses `capm admin quota <login|id> [--bytes SIZE] [--bundles N] [--reset]`.
func quotaArgs(args []string) (user string, bytes, bundles *int64, reset bool, err error) {
	var pos []string
	value := func(i *int, flag, inline string, hasInline bool) (string, error) {
		if hasInline {
			return inline, nil
		}
		if *i+1 >= len(args) {
			return "", fmt.Errorf("%s needs a value", flag)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		name, inline, hasInline := strings.Cut(args[i], "=")
		switch {
		case args[i] == "--reset":
			reset = true
		case name == "--bytes":
			v, e := value(&i, "--bytes", inline, hasInline)
			if e != nil {
				return "", nil, nil, false, e
			}
			n, e := parseSize(v)
			if e != nil {
				return "", nil, nil, false, fmt.Errorf("--bytes: %v", e)
			}
			bytes = &n
		case name == "--bundles":
			v, e := value(&i, "--bundles", inline, hasInline)
			if e != nil {
				return "", nil, nil, false, e
			}
			n, e := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if e != nil || n < 0 || n > maxSize {
				return "", nil, nil, false, fmt.Errorf("--bundles: %q is not a whole number of at least 0", v)
			}
			bundles = &n
		case strings.HasPrefix(args[i], "-") && args[i] != "-":
			return "", nil, nil, false, fmt.Errorf("unknown flag %q", client.Sanitize(args[i]))
		default:
			pos = append(pos, args[i])
		}
	}
	if len(pos) != 1 {
		return "", nil, nil, false, fmt.Errorf("expected 1 argument (a login or id), got %d", len(pos))
	}
	if reset && (bytes != nil || bundles != nil) {
		return "", nil, nil, false, errors.New("--reset cannot be combined with --bytes or --bundles")
	}
	return pos[0], bytes, bundles, reset, nil
}

// adminQuota shows or changes one user's storage quota.
func adminQuota(args []string, stdout, stderr io.Writer, e env) int {
	user, bytes, bundles, reset, err := quotaArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "capm admin quota: %v\n\n%s", err, adminUsage)
		return 2
	}
	creds, err := loadCreds(e)
	if err != nil {
		fmt.Fprintf(stderr, "capm admin: %v\n", err)
		return 1
	}
	defer warnExpiry(stderr, e, creds)
	c := client.New(e.registry, creds.Token)

	var q client.Quota
	changing := reset || bytes != nil || bundles != nil
	switch {
	case !changing:
		q, err = c.AdminQuota(user)
	case reset:
		q, err = c.AdminSetQuota(user, nil, nil)
	default:
		// The PUT replaces both overrides, so an override that is not being
		// changed is read first and sent back as it is.
		var cur client.Quota
		if cur, err = c.AdminQuota(user); err == nil {
			if bytes == nil && cur.BytesOverridden {
				bytes = &cur.MaxBytes
			}
			if bundles == nil && cur.BundlesOverridden {
				bundles = &cur.MaxBundles
			}
			q, err = c.AdminSetQuota(user, bytes, bundles)
		}
	}
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == 404 {
			fmt.Fprintln(stderr, "capm admin: not found (are you an admin on this registry?)")
			return 1
		}
		fmt.Fprintf(stderr, "capm admin quota: %v\n", err)
		return 1
	}
	if changing {
		fmt.Fprintf(stdout, "Updated the quota of %s\n", client.Sanitize(user))
	}
	tag := func(overridden bool) string {
		if overridden {
			return "override"
		}
		return "default"
	}
	storage := humanBytes(q.Bytes) + " (unlimited, " + tag(q.BytesOverridden) + ")"
	if q.MaxBytes > 0 {
		storage = fmt.Sprintf("%s of %s (%s)", humanBytes(q.Bytes), humanBytes(q.MaxBytes), tag(q.BytesOverridden))
	}
	bnd := fmt.Sprintf("%d (unlimited, %s)", q.Bundles, tag(q.BundlesOverridden))
	if q.MaxBundles > 0 {
		bnd = fmt.Sprintf("%d of %d (%s)", q.Bundles, q.MaxBundles, tag(q.BundlesOverridden))
	}
	fmt.Fprintf(stdout, "Quota for %s (id %d)\n", client.Sanitize(user), q.ID)
	fmt.Fprintf(stdout, "  storage:             %s\n", storage)
	fmt.Fprintf(stdout, "  bundles:             %s\n", bnd)
	fmt.Fprintf(stdout, "  versions per bundle: %s\n", limitOf(q.MaxBundleVersions, count))
	return 0
}
