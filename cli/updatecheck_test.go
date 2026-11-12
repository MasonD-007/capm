package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const noticeLine = "a newer capm is available (0.2.0); run capm self-update\n"

// noticeFixture is an env where the notice is allowed to fire (semver build,
// terminal stderr, empty environment) against a fake release at v0.2.0. A
// command that always succeeds is "known" because the registry is never
// contacted.
type noticeFixture struct {
	*updateFixture
	now  time.Time
	envs map[string]string
}

func newNoticeFixture(t *testing.T) *noticeFixture {
	t.Helper()
	f := &noticeFixture{updateFixture: newUpdateFixture(t, "0.1.0", "v0.2.0"), now: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC), envs: map[string]string{}}
	f.e.upd.stderrTTY = func() bool { return true }
	f.e.now = func() time.Time { return f.now }
	f.e.getenv = func(k string) string { return f.envs[k] }
	return f
}

func (f *noticeFixture) latestHits() int {
	f.fr.mu.Lock()
	defer f.fr.mu.Unlock()
	n := 0
	for _, h := range f.fr.hits {
		if h == "/releases/latest" {
			n++
		}
	}
	return n
}

func TestNoticePrintedAfterSuccessfulCommand(t *testing.T) {
	f := newNoticeFixture(t)
	code, _, errb := f.run("known")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.HasSuffix(errb, noticeLine) {
		t.Fatalf("notice should be the last stderr line: %q", errb)
	}
	if f.latestHits() != 1 {
		t.Fatalf("hits %d", f.latestHits())
	}
	f.fr.mu.Lock()
	defer f.fr.mu.Unlock()
	if f.fr.agents[0] != "capm/0.1.0" {
		t.Fatalf("user agent %q", f.fr.agents[0])
	}
}

func TestNoticeOncePerDay(t *testing.T) {
	f := newNoticeFixture(t)
	_, _, e1 := f.run("known")
	if !strings.Contains(e1, "newer capm") {
		t.Fatalf("first run: %q", e1)
	}
	f.now = f.now.Add(23*time.Hour + 59*time.Minute)
	_, _, e2 := f.run("known")
	if strings.Contains(e2, "newer capm") || f.latestHits() != 1 {
		t.Fatalf("within 24h: %q hits %d", e2, f.latestHits())
	}
	f.now = f.now.Add(2 * time.Minute)
	_, _, e3 := f.run("known")
	if !strings.Contains(e3, "newer capm") || f.latestHits() != 2 {
		t.Fatalf("after 24h: %q hits %d", e3, f.latestHits())
	}
}

func TestNoticeStateFile(t *testing.T) {
	f := newNoticeFixture(t)
	f.run("known")
	p := filepath.Join(f.e.credDir, "update-check.json")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	st := f.e.loadUpdateCheck()
	if !st.CheckedAt.Equal(f.now) || st.Latest != "0.2.0" {
		t.Fatalf("state %+v", st)
	}
	ents, _ := os.ReadDir(f.e.credDir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".update-check-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestNoticeCorruptStateIsNeverChecked(t *testing.T) {
	f := newNoticeFixture(t)
	os.WriteFile(filepath.Join(f.e.credDir, "update-check.json"), []byte("{not json"), 0o600)
	_, _, errb := f.run("known")
	if !strings.Contains(errb, "newer capm") {
		t.Fatalf("corrupt state should behave as never checked: %q", errb)
	}
}

func TestNoticeNotPrintedWhenCurrentOrAhead(t *testing.T) {
	for _, cur := range []string{"0.2.0", "0.3.0", "1.0.0"} {
		f := newNoticeFixture(t)
		setVersion(t, cur)
		if _, _, errb := f.run("known"); strings.Contains(errb, "newer capm") {
			t.Fatalf("%s: %q", cur, errb)
		}
		if f.latestHits() != 1 {
			t.Fatalf("%s: should still have checked once", cur)
		}
	}
}

func TestNoticeSuppression(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	cases := []struct {
		name  string
		setup func(f *noticeFixture)
		args  []string
	}{
		{"CAPM_NO_UPDATE_CHECK set", func(f *noticeFixture) { f.envs["CAPM_NO_UPDATE_CHECK"] = "1" }, []string{"known"}},
		{"CI set", func(f *noticeFixture) { f.envs["CI"] = "true" }, []string{"known"}},
		{"stderr not a terminal", func(f *noticeFixture) { f.e.upd.stderrTTY = func() bool { return false } }, []string{"known"}},
		{"dev build", func(f *noticeFixture) { setVersion(t, "dev") }, []string{"known"}},
		{"sha build", func(f *noticeFixture) { setVersion(t, sha) }, []string{"known"}},
		{"version command", func(f *noticeFixture) {}, []string{"version"}},
		{"self-update command", func(f *noticeFixture) {}, []string{"self-update", "--check"}},
		{"__complete command", func(f *noticeFixture) {}, []string{"__complete", "x"}},
		{"help", func(f *noticeFixture) {}, []string{"help"}},
		{"no arguments", func(f *noticeFixture) {}, nil},
		{"usage error", func(f *noticeFixture) {}, []string{"list", "a", "b"}},
		{"unknown command", func(f *noticeFixture) {}, []string{"bogus"}},
		{"failed command", func(f *noticeFixture) {}, []string{"known", "forget", "not-a-ref"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newNoticeFixture(t)
			c.setup(f)
			_, _, errb := f.run(c.args...)
			if strings.Contains(errb, "newer capm") {
				t.Fatalf("notice printed: %q", errb)
			}
			if c.args != nil && c.args[0] == "self-update" {
				return // self-update itself fetches latest once
			}
			if n := f.latestHits(); n != 0 {
				t.Fatalf("made %d request(s); a suppressed notice must not even check", n)
			}
			if _, err := os.Stat(filepath.Join(f.e.credDir, "update-check.json")); err == nil {
				t.Fatal("state file written although suppressed")
			}
		})
	}
}

func TestNoticeEmptyEnvVarsDoNotSuppress(t *testing.T) {
	f := newNoticeFixture(t)
	f.envs["CAPM_NO_UPDATE_CHECK"] = ""
	f.envs["CI"] = ""
	if _, _, errb := f.run("known"); !strings.Contains(errb, "newer capm") {
		t.Fatalf("%q", errb)
	}
}

func TestNoticeNeverFailsOrBlocksTheCommand(t *testing.T) {
	// A server that never answers: the check must give up on its own budget.
	release := make(chan struct{})
	var hits atomic.Int32
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); hang.Close() })
	f := newNoticeFixture(t)
	f.e.upd.latestURL = hang.URL + "/releases/latest"
	f.e.upd.timeout = 150 * time.Millisecond
	start := time.Now()
	code, _, errb := f.run("known")
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
	if code != 0 || strings.Contains(errb, "newer capm") || strings.Contains(errb, "context") || strings.Contains(errb, "timeout") {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	// The failed attempt counts: an offline machine is not charged every time.
	f.run("known")
	if hits.Load() != 1 {
		t.Fatalf("retried within a day: %d", hits.Load())
	}
}

func TestNoticeErrorsAreSilent(t *testing.T) {
	f := newNoticeFixture(t)
	f.fr.srv.Close()
	code, out, errb := f.run("known")
	if code != 0 || strings.Contains(errb, "capm: ") && strings.Contains(errb, "lookup") {
		t.Fatalf("exit %d out %q err %q", code, out, errb)
	}
	if strings.Contains(errb, "dial") || strings.Contains(errb, "refused") {
		t.Fatalf("error leaked: %q", errb)
	}
}

func TestNoticeTimeoutDefault(t *testing.T) {
	if updateCheckTimeout != 1500*time.Millisecond {
		t.Fatalf("budget %v", updateCheckTimeout)
	}
}

func TestNoticeSanitisesLatest(t *testing.T) {
	f := newNoticeFixture(t)
	f.fr.tag = "v0.2.0"
	var out bytes.Buffer
	f.e.maybeNotifyUpdate([]string{"known"}, 0, &out)
	if out.String() != noticeLine {
		t.Fatalf("%q", out.String())
	}
}
