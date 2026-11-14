package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/MasonD-007/capm/backend/internal/store"
)

// signatureRoute is the second (and last) authenticated route a publish-scoped
// token may call: a CI workflow that just published a version signs it.
const signatureRoute = "PUT /v1/bundles/{owner}/{name}/{version}/signature"

// scopedPublishRoute reports whether a publish-scoped token may call the route
// pattern: exactly publishRoute and signatureRoute, nothing else. Everything
// else is refused to it; drift tests assert the pair.
func scopedPublishRoute(pattern string) bool {
	return pattern == publishRoute || pattern == signatureRoute
}

const sigMediaTypePrefix = "application/vnd.dev.sigstore.bundle"

// notVerified is part of every 400 about the shape, so nobody reads a
// successful upload as an endorsement.
const notVerified = "the registry does not verify signatures, it only checks the shape of the upload: "

// checkSignatureShape is a cheap sanity check, explicitly NOT verification: the
// body is a JSON object with a string mediaType that names a Sigstore bundle,
// and object-valued verificationMaterial and messageSignature. The CLI does
// the verifying; a bundle that passes here may still be worthless.
func checkSignatureShape(body []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil || top == nil {
		return errors.New("the body is not a JSON object")
	}
	var mt string
	if err := json.Unmarshal(top["mediaType"], &mt); err != nil || !strings.HasPrefix(mt, sigMediaTypePrefix) {
		return errors.New(`"mediaType" must be a string starting with "` + sigMediaTypePrefix + `"`)
	}
	for _, k := range []string{"verificationMaterial", "messageSignature"} {
		var o map[string]json.RawMessage
		if err := json.Unmarshal(top[k], &o); err != nil || o == nil {
			return errors.New(`"` + k + `" must be a JSON object`)
		}
	}
	return nil
}

// putSignature stores the Sigstore bundle a CI workflow produced for a
// version. It authorises exactly like publishing (the one AuthorizeOwner
// decision) and has its own per-user hourly allowance. The registry never
// verifies the bundle; see store.PutSignature.
func (a *API) putSignature(w http.ResponseWriter, r *http.Request) {
	tk, ok := a.caller(w, r)
	if !ok {
		return
	}
	owner, name, version := r.PathValue("owner"), r.PathValue("name"), r.PathValue("version")
	acc, ok := a.authorizeOwner(w, r, tk, owner, actPublish)
	if !ok {
		return
	}
	// A separate allowance of the same size as the publish one: signing must
	// not eat publish slots (a CI run publishes and signs), nor be unlimited.
	// Like publish, a rejected upload still counts.
	if ok, retry := a.signLim.Allow(strconv.FormatInt(tk.UserID, 10)); !ok {
		tooMany(w, retry)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeErr(w, 400, notVerified+"the Content-Type must be application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, store.MaxSignatureBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, 413, "signature bundle too large (at most 65536 bytes)")
		} else {
			writeErr(w, 400, "could not read body")
		}
		return
	}
	if err := checkSignatureShape(body); err != nil {
		writeErr(w, 400, notVerified+err.Error())
		return
	}
	err = a.store.PutSignature(acc.Owner.ID, name, version, body, acc.PublishedBy)
	switch {
	case err == nil:
		writeJSON(w, 201, map[string]string{})
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, 404, "version not found")
	case errors.Is(err, store.ErrSignatureExists):
		writeErr(w, 409, "this version already has a signature (signatures are write-once; publish a new version to sign again)")
	case errors.Is(err, store.ErrSignatureTooLarge):
		writeErr(w, 413, "signature bundle too large (at most 65536 bytes)")
	default:
		internal(w, err)
	}
}

// getSignature serves the stored bytes exactly as uploaded. No authentication;
// 404 for a version without one, that does not exist, was removed, or whose
// owner is banned.
func (a *API) getSignature(w http.ResponseWriter, r *http.Request) {
	b, err := a.store.Signature(r.PathValue("owner"), r.PathValue("name"), r.PathValue("version"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "no signature")
		return
	}
	if err != nil {
		internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		io.Copy(w, bytes.NewReader(b))
	}
}
