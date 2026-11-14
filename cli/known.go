package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/MasonD-007/capm/manifest"
)

// known.json is the CLI's memory of what this user has pulled or run before:
// the owner each bundle belonged to (owner pinning) and the permissions of the
// version last run (permission diff). It lives next to credentials.json:
//
//	{
//	  "version": 1,
//	  "registries": {
//	    "<registry URL>": {
//	      "<owner>/<name>": {
//	        "ownerId": 123,
//	        "pinnedAt": "2026-11-11T10:00:00Z",
//	        "lastRun": {"version": "1.0.0", "digest": "sha256:...",
//	                    "manifest": {...}, "at": "2026-11-11T10:00:00Z"},
//	        "signerPin": {"ownerId": 123, "repositoryId": 456,
//	                      "repository": "owner/repo", "verifiedVersion": "1.0.0",
//	                      "at": "2026-11-11T10:00:00Z"}
//	      }
//	    }
//	  }
//	}
//
// The owner part of a key is lower-cased (GitHub logins are case-insensitive).
// Unknown fields at the top level and in a record are preserved on rewrite.
const knownFileName = "known.json"

type lastRun struct {
	Version  string             `json:"version"`
	Digest   string             `json:"digest"`
	Manifest *manifest.Manifest `json:"manifest,omitempty"`
	At       time.Time          `json:"at"`
}

type knownRecord struct {
	// OwnerID is the GitHub numeric id pinned for this name; 0 means not pinned
	// (the registry did not report one).
	OwnerID  int64     `json:"ownerId"`
	PinnedAt time.Time `json:"pinnedAt"`
	LastRun  *lastRun  `json:"lastRun,omitempty"`
	// SignerPin is the GitHub repository whose workflow signed a version of this
	// bundle that capm verified, pinned on first use. nil: no signed version
	// has been verified on this machine. Older files have no such member.
	SignerPin *signerPin `json:"signerPin,omitempty"`

	extra map[string]json.RawMessage
}

// signerPin is what a verified signature taught capm about who signs this
// bundle. Every value comes from the verified certificate, never from the
// registry.
type signerPin struct {
	OwnerID      int64  `json:"ownerId"`
	RepositoryID int64  `json:"repositoryId"`
	Repository   string `json:"repository"` // owner/repo, for display
	// VerifiedVersion is the newest version whose signature capm verified.
	VerifiedVersion string    `json:"verifiedVersion"`
	At              time.Time `json:"at"`

	extra map[string]json.RawMessage
}

type signerAlias signerPin

func (p *signerPin) UnmarshalJSON(b []byte) (err error) {
	p.extra, err = unmarshalKeepExtra(b, (*signerAlias)(p), "ownerId", "repositoryId", "repository", "verifiedVersion", "at")
	return err
}

func (p signerPin) MarshalJSON() ([]byte, error) {
	return marshalWithExtra(signerAlias(p), p.extra)
}

type knownState struct {
	Version    int                                `json:"version"`
	Registries map[string]map[string]*knownRecord `json:"registries"`

	extra map[string]json.RawMessage
}

type (
	recordAlias knownRecord
	stateAlias  knownState
)

func (r *knownRecord) UnmarshalJSON(b []byte) (err error) {
	r.extra, err = unmarshalKeepExtra(b, (*recordAlias)(r), "ownerId", "pinnedAt", "lastRun", "signerPin")
	return err
}

func (r knownRecord) MarshalJSON() ([]byte, error) {
	return marshalWithExtra(recordAlias(r), r.extra)
}

func (s *knownState) UnmarshalJSON(b []byte) (err error) {
	s.extra, err = unmarshalKeepExtra(b, (*stateAlias)(s), "version", "registries")
	return err
}

func (s knownState) MarshalJSON() ([]byte, error) {
	return marshalWithExtra(stateAlias(s), s.extra)
}

func unmarshalKeepExtra(b []byte, v any, known ...string) (map[string]json.RawMessage, error) {
	if err := json.Unmarshal(b, v); err != nil {
		return nil, err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	for _, k := range known {
		delete(all, k)
	}
	if len(all) == 0 {
		return nil, nil
	}
	return all, nil
}

func marshalWithExtra(v any, extra map[string]json.RawMessage) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || len(extra) == 0 {
		return b, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, raw := range extra {
		if _, ok := m[k]; !ok {
			m[k] = raw
		}
	}
	return json.Marshal(m)
}

// knownStore reads and writes known.json. Every operation re-reads the file,
// so a write only loses changes made by another capm between its own read and
// its rename (last writer wins); the file itself is replaced atomically and is
// never partial.
type knownStore struct {
	dir    string
	stderr io.Writer
	warned bool
}

func newKnownStore(e env, stderr io.Writer) *knownStore {
	return &knownStore{dir: e.credDir, stderr: stderr}
}

func (k *knownStore) path() string { return filepath.Join(k.dir, knownFileName) }

func (k *knownStore) warn(format string, a ...any) {
	if k.warned {
		return
	}
	k.warned = true
	fmt.Fprintf(k.stderr, "warning: "+format+"\n", a...)
}

// load returns the current state. A missing file is empty; an unreadable or
// corrupt one is treated as empty with a single warning per store, and is left
// untouched until the next successful write replaces it.
func (k *knownStore) load() *knownState {
	st := &knownState{Version: 1}
	if k.dir == "" {
		k.warn("cannot determine a config directory; capm cannot remember previous runs")
		return st
	}
	b, err := os.ReadFile(k.path())
	if errors.Is(err, os.ErrNotExist) {
		return st
	}
	if err == nil {
		var parsed knownState
		if err = json.Unmarshal(b, &parsed); err == nil {
			if parsed.Version == 0 {
				parsed.Version = 1
			}
			return &parsed
		}
	}
	k.warn("%s is unreadable or corrupt (%v); ignoring it, and it will be replaced the next time capm records a run", k.path(), err)
	return st
}

func knownKey(owner, name string) string { return strings.ToLower(owner) + "/" + name }

func (k *knownStore) get(registry, owner, name string) (knownRecord, bool) {
	r := k.load().Registries[registry][knownKey(owner, name)]
	if r == nil {
		return knownRecord{}, false
	}
	return *r, true
}

// update loads the current state, lets fn modify (or create) the record for
// registry+owner/name, and writes the result atomically.
func (k *knownStore) update(registry, owner, name string, fn func(*knownRecord)) error {
	st := k.load()
	if k.dir == "" {
		return errors.New("cannot determine a config directory")
	}
	if st.Registries == nil {
		st.Registries = map[string]map[string]*knownRecord{}
	}
	if st.Registries[registry] == nil {
		st.Registries[registry] = map[string]*knownRecord{}
	}
	key := knownKey(owner, name)
	r := st.Registries[registry][key]
	if r == nil {
		r = &knownRecord{}
		st.Registries[registry][key] = r
	}
	fn(r)
	return k.save(st)
}

// forget removes the record, reporting whether there was one.
func (k *knownStore) forget(registry, owner, name string) (bool, error) {
	st := k.load()
	key := knownKey(owner, name)
	if st.Registries[registry][key] == nil {
		return false, nil
	}
	delete(st.Registries[registry], key)
	if len(st.Registries[registry]) == 0 {
		delete(st.Registries, registry)
	}
	return true, k.save(st)
}

type knownEntry struct {
	Registry string
	Key      string // owner/name
	Record   knownRecord
}

// all lists every record, sorted by registry then key.
func (k *knownStore) all() []knownEntry {
	var out []knownEntry
	for reg, m := range k.load().Registries {
		for key, r := range m {
			if r != nil {
				out = append(out, knownEntry{reg, key, *r})
			}
		}
	}
	slices.SortFunc(out, func(a, b knownEntry) int {
		if c := strings.Compare(a.Registry, b.Registry); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

// save writes st to a temp file in the same directory (mode 0600), then
// renames it over known.json.
func (k *knownStore) save(st *knownState) error {
	if err := os.MkdirAll(k.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(k.dir, ".known-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), k.path())
}
