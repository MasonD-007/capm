package api

import (
	"encoding/json"
	"testing"
)

// resolve and metadata report the owner's GitHub numeric id (the same value
// list reports) so a client can pin it.
func TestResolveAndMetadataReportOwnerID(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	e.user.id = 4242
	publishVersions(t, e, "1.0.0")
	e.user.ok = false

	for _, path := range []string{"/v1/bundles/alice/x/resolve", "/v1/bundles/alice/x/1.0.0"} {
		c, b := e.do(t, "GET", path, nil)
		if c != 200 {
			t.Fatalf("%s: %d %s", path, c, b)
		}
		var got struct {
			OwnerID int64  `json:"ownerId"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got.OwnerID != 4242 || got.Version != "1.0.0" {
			t.Errorf("%s: %+v", path, got)
		}
	}

	_, b := e.do(t, "GET", "/v1/bundles?owner=alice", nil)
	var l []struct {
		OwnerID int64 `json:"ownerId"`
	}
	if err := json.Unmarshal(b, &l); err != nil || len(l) != 1 || l[0].OwnerID != 4242 {
		t.Errorf("list: %v %s", err, b)
	}
}
