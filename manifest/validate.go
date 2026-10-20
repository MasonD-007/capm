package manifest

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
)

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	secretRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	// Official semver.org regexp.
	semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
		`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	// Lowercase DNS labels; the final label must contain a letter, which
	// rules out IPv4 literals.
	hostRe   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	hasAlpha = regexp.MustCompile(`[a-z][^.]*$`)
)

// Validate checks every rule and returns all problems joined.
func (m *Manifest) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if !nameRe.MatchString(m.Metadata.Name) {
		add("metadata.name %q must match %s", m.Metadata.Name, nameRe)
	}
	if !semverRe.MatchString(m.Metadata.Version) {
		add("metadata.version %q must be semver", m.Metadata.Version)
	}
	switch m.Base.Agent {
	case "claude-code", "opencode":
	default:
		add("base.agent %q must be claude-code or opencode", m.Base.Agent)
	}
	if m.Interface.Type != "tty" {
		add("interface.type %q must be tty", m.Interface.Type)
	}
	for i, h := range m.Permissions.Egress {
		if len(h) > 253 || !hostRe.MatchString(h) || !hasAlpha.MatchString(h) {
			add("permissions.egress[%d] %q must be a lowercase hostname", i, h)
		}
	}
	for i, mt := range m.Permissions.Mounts {
		if !localPath(mt.Path) {
			add("permissions.mounts[%d].path %q must be a relative path inside the workspace", i, mt.Path)
		}
		if mt.Mode != "read-only" && mt.Mode != "read-write" {
			add("permissions.mounts[%d].mode %q must be read-only or read-write", i, mt.Mode)
		}
	}
	declared := map[string]bool{}
	for i, s := range m.Secrets {
		if !secretRe.MatchString(s.Name) {
			add("secrets[%d].name %q must match %s", i, s.Name, secretRe)
		}
		declared[s.Name] = true
	}
	for i, c := range m.MCP {
		u, err := url.Parse(c.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			add("mcp[%d].url %q must be an https URL", i, c.URL)
		}
		if c.Secret != "" && !declared[c.Secret] {
			add("mcp[%d].secret %q is not declared in secrets", i, c.Secret)
		}
	}
	for i, p := range m.Context {
		if !localPath(p) {
			add("context[%d] %q must be a relative path inside the bundle", i, p)
		}
	}
	return errors.Join(errs...)
}

// localPath reports whether p is a non-empty relative path that stays inside
// its root after cleaning.
func localPath(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.IsLocal(p)
}
