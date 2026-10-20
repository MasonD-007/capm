package manifest

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
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

	// Everything the manifest author controls is shown to the installer, so
	// control characters (newline, ESC, ...) are rejected everywhere.
	noCtl := func(field, s string) {
		if hasControl(s) {
			add("%s must not contain control characters", field)
		}
	}
	noCtl("metadata.name", m.Metadata.Name)
	noCtl("metadata.version", m.Metadata.Version)
	noCtl("metadata.description", m.Metadata.Description)
	for i, a := range m.Metadata.Authors {
		noCtl(fmt.Sprintf("metadata.authors[%d]", i), a)
	}
	noCtl("base.agent", m.Base.Agent)
	noCtl("base.version", m.Base.Version)
	if m.Base.Version == "" || strings.IndexFunc(m.Base.Version, unicode.IsSpace) >= 0 {
		add("base.version must be non-empty and contain no whitespace")
	}
	noCtl("interface.type", m.Interface.Type)
	noCtl("model.api", m.Model.API)
	for i, h := range m.Permissions.Egress {
		noCtl(fmt.Sprintf("permissions.egress[%d]", i), h)
	}
	for i, mt := range m.Permissions.Mounts {
		noCtl(fmt.Sprintf("permissions.mounts[%d].path", i), mt.Path)
		noCtl(fmt.Sprintf("permissions.mounts[%d].mode", i), mt.Mode)
	}
	for i, s := range m.Secrets {
		noCtl(fmt.Sprintf("secrets[%d].name", i), s.Name)
		noCtl(fmt.Sprintf("secrets[%d].description", i), s.Description)
	}
	for i, c := range m.MCP {
		noCtl(fmt.Sprintf("mcp[%d].name", i), c.Name)
		noCtl(fmt.Sprintf("mcp[%d].url", i), c.URL)
		noCtl(fmt.Sprintf("mcp[%d].secret", i), c.Secret)
	}
	for i, p := range m.Context {
		noCtl(fmt.Sprintf("context[%d]", i), p)
	}

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
		} else if u.User != nil {
			add("mcp[%d].url must not contain userinfo (manifests hold secret names only)", i)
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

func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}
