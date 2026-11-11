package manifest

import (
	"errors"
	"fmt"
	"net/url"
	"path"
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
	if m.APIVersion != "capm/v0" {
		add("apiVersion %q must be capm/v0", m.APIVersion)
	}
	if m.Kind != "Agent" {
		add("kind %q must be Agent", m.Kind)
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
	mcpNames := map[string]bool{}
	for i, c := range m.MCP {
		// MCP names become sbx registry names and are joined into
		// comma-separated --static-mcp lists and mcp:<server>:<key> secret
		// names, so only plain lowercase labels are allowed.
		if !nameRe.MatchString(c.Name) {
			add("mcp[%d].name %q must match %s", i, c.Name, nameRe)
		} else if mcpNames[c.Name] {
			add("mcp[%d].name %q is a duplicate", i, c.Name)
		}
		mcpNames[c.Name] = true
		if _, err := MCPHost(c.URL); err != nil {
			add("mcp[%d].url %q %v", i, c.URL, err)
		}
		if c.Secret != "" && !declared[c.Secret] {
			add("mcp[%d].secret %q is not declared in secrets", i, c.Secret)
		}
	}
	for i, p := range m.Context {
		// The path is written into a header line of the generated kit
		// context ("<!-- capm context file: PATH -->"), which sbx expands
		// ${{ ... }} in, so neither may appear; and it must already be in
		// clean form so what inspect shows is exactly the file read.
		switch {
		case !localPath(p) || path.Clean(p) != p:
			add("context[%d] %q must be a clean relative path inside the bundle", i, p)
		case strings.Contains(p, "${{") || strings.Contains(p, "-->"):
			add("context[%d] %q must not contain \"${{\" or \"-->\"", i, p)
		}
	}
	return errors.Join(errs...)
}

// localPath reports whether p is a non-empty relative path that stays inside
// its root after cleaning.
func localPath(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.IsLocal(p)
}

// MCPHost checks an MCP server URL and returns its lowercase hostname. The
// host gets the same rules as permissions.egress (exact DNS name, no IP
// literal), plus: no userinfo, port absent or 443, and no names that only
// make sense on the installer's own network (localhost, .local, .internal).
func MCPHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return "", errors.New("must be an https URL")
	}
	if u.User != nil {
		return "", errors.New("must not contain userinfo (manifests hold secret names only)")
	}
	if strings.HasPrefix(u.Host, "[") {
		return "", errors.New("must name a host, not an IP address")
	}
	if strings.HasSuffix(u.Host, ":") || (u.Port() != "" && u.Port() != "443") {
		return "", errors.New("must use the default https port (443)")
	}
	h := strings.ToLower(u.Hostname())
	if len(h) > 253 || !hostRe.MatchString(h) || !hasAlpha.MatchString(h) {
		return "", errors.New("must have a plain DNS hostname (no IP address, no trailing dot)")
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") ||
		strings.HasSuffix(h, ".local") || h == "local" ||
		strings.HasSuffix(h, ".internal") || h == "internal" {
		return "", errors.New("must not name a local-network host (localhost, .local, .internal)")
	}
	return h, nil
}

// hasControl reports characters that can corrupt or disguise terminal and
// web output: Unicode control characters (C0, DEL, C1 including NEL), line
// and paragraph separators, and bidi embedding/override/isolate/mark
// characters, which can visually reorder text.
func hasControl(s string) bool {
	return strings.IndexFunc(s, IsUnsafeRune) >= 0
}

// IsUnsafeRune reports whether r is one of the characters hasControl rejects.
func IsUnsafeRune(r rune) bool {
	switch {
	case unicode.IsControl(r):
		return true
	case r == '\u2028', r == '\u2029': // line / paragraph separator
		return true
	case r >= '\u202a' && r <= '\u202e': // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= '\u2066' && r <= '\u2069': // LRI, RLI, FSI, PDI
		return true
	case r == '\u200e', r == '\u200f', r == '\u061c': // LRM, RLM, ALM
		return true
	}
	return false
}

// DisplaySafe returns s with every character hasControl rejects replaced by
// U+FFFD. Validate already refuses such manifests; this is defence in depth
// for code paths that print manifest strings.
func DisplaySafe(s string) string {
	if !hasControl(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if IsUnsafeRune(r) {
			return '\uFFFD'
		}
		return r
	}, s)
}
