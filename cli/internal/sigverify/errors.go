package sigverify

import (
	"errors"
	"fmt"
	"strings"
)

// The error kinds Verify can return. Test with errors.Is; a caller that needs
// the library's own error (for debugging) can walk the chain with errors.Unwrap.
var (
	// ErrInvalidInput: the caller's arguments are unusable (digest not 32
	// bytes, bundle over MaxBundleSize, an Expect that cannot be satisfied).
	ErrInvalidInput = errors.New("sigverify: invalid input")

	// ErrMalformed: the bytes are not a Sigstore bundle of the one shape this
	// package accepts (v0.3, one message signature, a Fulcio certificate, one
	// transparency-log entry).
	ErrMalformed = errors.New("sigverify: malformed or unsupported bundle")

	// ErrUntrusted: the bundle is well formed but a cryptographic or
	// transparency-log check failed: the certificate does not chain to the
	// embedded Fulcio root, the SCT, the Rekor proof or signed entry timestamp
	// does not verify, or the signature is not over the given digest.
	ErrUntrusted = errors.New("sigverify: signature not trusted")

	// ErrIdentity: the signature is cryptographically valid but the signer is
	// not who the policy requires. The concrete error is an *IdentityError.
	ErrIdentity = errors.New("sigverify: signer identity rejected")

	// ErrStaleTrustRoot: the Sigstore trust material embedded in this build
	// does not cover this signature (an unknown transparency log or
	// certificate authority, or nothing in it is currently valid). The caller
	// should tell the user to update capm. The concrete error is a
	// *StaleTrustRootError.
	ErrStaleTrustRoot = errors.New("sigverify: embedded trust root does not cover this signature")
)

// Error is the common error type: a Kind (one of the sentinels above), a short
// fixed Detail written by this package, and optionally the wrapped library
// error. Error() never prints the wrapped error unsanitised.
type Error struct {
	Kind   error
	Detail string
	Err    error
}

func (e *Error) Error() string {
	s := e.Kind.Error()
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Err != nil {
		s += ": " + sanitize(e.Err.Error(), maxMsg)
	}
	return s
}

// Unwrap exposes both the kind and the library error to errors.Is/As.
func (e *Error) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Err}
}

func newErr(kind error, detail string, err error) error {
	return &Error{Kind: kind, Detail: detail, Err: err}
}

// IdentityError says which field of the signing identity failed the policy.
// Want is the caller's own expectation; Got is what the certificate carried,
// and is set only when it has the shape of a legitimate GitHub value (it is
// otherwise empty), so an attacker-chosen certificate cannot inject text.
type IdentityError struct {
	Field string // fixed vocabulary: "issuer", "owner login", "owner id", "repository", "repository id", "workflow", "certificate"
	Want  string
	Got   string
	// Reason is a fixed phrase: "mismatch", "missing", or "malformed".
	Reason string
}

func (e *IdentityError) Error() string {
	s := fmt.Sprintf("%s: %s %s", ErrIdentity.Error(), e.Field, e.Reason)
	if e.Want != "" {
		s += fmt.Sprintf(": expected %q", sanitize(e.Want, 64))
	}
	if e.Got != "" {
		s += fmt.Sprintf(", certificate has %q", sanitize(e.Got, 64))
	}
	return s
}

func (e *IdentityError) Is(target error) bool { return target == ErrIdentity }

// StaleTrustRootError reports that this build's embedded trust root cannot
// vouch for the signature. Reason is one of a fixed set of phrases.
//
// This can mean "Sigstore rotated a key after this capm was built" or "the
// bundle was made under a CA this capm never trusted"; the two are not
// distinguishable offline, and both are refused. Callers must treat it as a
// refusal, never as a downgrade to "unsigned".
type StaleTrustRootError struct {
	Reason string
}

func (e *StaleTrustRootError) Error() string {
	return ErrStaleTrustRoot.Error() + ": " + e.Reason
}

func (e *StaleTrustRootError) Is(target error) bool { return target == ErrStaleTrustRoot }

const maxMsg = 200

// sanitize makes s safe to print: printable ASCII only (anything else becomes
// '?'), at most max bytes.
func sanitize(s string, max int) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); i++ {
		if n >= max {
			b.WriteString("...")
			break
		}
		c := s[i]
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b.WriteByte(c)
		n++
	}
	return b.String()
}
