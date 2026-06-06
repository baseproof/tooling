package bytestore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// TestNamespacedKey pins the chokepoint helper: a non-empty namespace prepends a
// single segment; an empty namespace is the identity (the flat, pre-namespace
// layout, back-compat).
func TestNamespacedKey(t *testing.T) {
	cases := []struct{ ns, key, want string }{
		{"", "cosigned-checkpoint", "cosigned-checkpoint"},
		{"", "tile/0/x000/000", "tile/0/x000/000"},
		{"log-A", "cosigned-checkpoint", "log-A/cosigned-checkpoint"},
		{"log-A", "tile/0/x000/000", "log-A/tile/0/x000/000"},
	}
	for _, c := range cases {
		if got := namespacedKey(c.ns, c.key); got != c.want {
			t.Errorf("namespacedKey(%q,%q) = %q, want %q", c.ns, c.key, got, c.want)
		}
	}
}

// TestNamespaceForLog pins the shared per-log derivation used by the ledger AND
// every offline reader: deterministic, collision-resistant, object-key-safe, with
// a readable prefix. Identical resolution across components is what keeps a
// reader pointed at the same subtree the writer used.
func TestNamespaceForLog(t *testing.T) {
	if got := NamespaceForLog(""); got != "" {
		t.Errorf("NamespaceForLog(\"\") = %q, want empty (flat layout)", got)
	}
	a := NamespaceForLog("did:web:baseproof:federal")
	b := NamespaceForLog("did:web:baseproof:tn")
	if a == b {
		t.Fatalf("distinct DIDs produced the same namespace %q", a)
	}
	if a != NamespaceForLog("did:web:baseproof:federal") {
		t.Error("NamespaceForLog is not deterministic")
	}
	if strings.ContainsAny(a, ":/ ") {
		t.Errorf("namespace %q contains object-key-unsafe characters", a)
	}
	if !strings.HasPrefix(a, "did_web_baseproof_federal-") {
		t.Errorf("namespace %q missing readable sanitized prefix", a)
	}
}

// TestS3_Namespace_IsolatesRawSurface is the CI-runnable proof of the fix: the
// fixed-name raw objects (the cosigned-checkpoint horizon, the SMT tiles) of two
// distinct logs can NEVER land on the same key in a shared bucket, while the
// content-addressed entry surface stays flat (un-namespaced) so the offline
// readers and the 302 PublicURL keep resolving it without a namespace handshake.
func TestS3_Namespace_IsolatesRawSurface(t *testing.T) {
	hash := sha256.Sum256([]byte("k"))
	a := &S3{namespace: "log-A", objectPrefix: "entries"}
	b := &S3{namespace: "log-B", objectPrefix: "entries"}

	// Entries are content-addressed and NOT namespaced: same (seq,hash) → same
	// flat key under either namespace; two logs never collide because distinct
	// content yields a distinct hash (and thus a distinct key).
	if got, want := a.keyOf(7, hash), fmt.Sprintf("entries/%02x/%016x/%x", hash[0], uint64(7), hash[:]); got != want {
		t.Errorf("entry keyOf = %q, want %q (entries are not namespaced)", got, want)
	}
	if a.keyOf(7, hash) != b.keyOf(7, hash) {
		t.Error("entry keyOf must be namespace-independent (content-addressed surface)")
	}

	// The fixed-name cosigned-checkpoint horizon IS namespaced on the raw surface,
	// so two logs never share that single global key — the proven clobber fix.
	if a.nsKey(cosignedCheckpointProbe) == b.nsKey(cosignedCheckpointProbe) {
		t.Fatal("two logs produced the SAME raw key for the cosigned-checkpoint — last writer would clobber the horizon")
	}
	if got, want := a.nsKey(cosignedCheckpointProbe), "log-A/cosigned-checkpoint"; got != want {
		t.Errorf("raw nsKey = %q, want %q", got, want)
	}
	// SMT tile paths are namespaced the same way (the whole raw surface).
	if got, want := a.nsKey("tile/0/x001/002"), "log-A/tile/0/x001/002"; got != want {
		t.Errorf("raw tile nsKey = %q, want %q", got, want)
	}

	// Empty namespace preserves the flat legacy layout (single-log bucket opt-out).
	flat := &S3{namespace: "", objectPrefix: "entries"}
	if got, want := flat.nsKey(cosignedCheckpointProbe), "cosigned-checkpoint"; got != want {
		t.Errorf("empty-namespace raw key = %q, want %q (flat layout)", got, want)
	}
}

// cosignedCheckpointProbe mirrors store.cosignedCheckpointKey ("cosigned-checkpoint")
// — the fixed object name the horizon publisher PutObjects. Duplicated as a test
// constant (the store package can't be imported here without a cycle) to pin that
// THIS exact key is namespaced.
const cosignedCheckpointProbe = "cosigned-checkpoint"

// TestS3_Namespace_RawObjectIsolation_Live proves end-to-end on a real S3-
// compatible backend that two logs writing the SAME fixed-name object under
// DIFFERENT namespaces do not clobber each other. Env-gated (skips in unit CI;
// runs in the integration harness alongside the other requireS3 tests).
func TestS3_Namespace_RawObjectIsolation_Live(t *testing.T) {
	ctx := context.Background()
	base := requireS3(t) // gates on BASEPROOF_TEST_S3_* / real-S3; shares one bucket

	// Two stores on the SAME bucket, DIFFERENT namespace. Fresh structs (NOT a copy
	// of base — that would copy its sync.Mutex) sharing the client pointer, each
	// with its own cache so a hit can't mask a clobber. The namespaces extend
	// base's unique per-test prefix so base's t.Cleanup deletes both subtrees.
	mk := func(ns string) *S3 {
		return &S3{
			client:       base.client,
			bucket:       base.bucket,
			namespace:    ns,
			objectPrefix: base.objectPrefix,
			writeTimeout: base.writeTimeout,
			readTimeout:  base.readTimeout,
			cache:        map[string][]byte{},
			access:       map[string]int64{},
			maxSize:      16,
		}
	}
	a, b := mk(base.objectPrefix+"-A"), mk(base.objectPrefix+"-B")

	if err := a.PutObject(ctx, cosignedCheckpointProbe, []byte("A horizon")); err != nil {
		t.Fatalf("A PutObject: %v", err)
	}
	if err := b.PutObject(ctx, cosignedCheckpointProbe, []byte("B horizon")); err != nil {
		t.Fatalf("B PutObject: %v", err)
	}
	gotA, err := a.GetObject(ctx, cosignedCheckpointProbe)
	if err != nil {
		t.Fatalf("A GetObject: %v", err)
	}
	gotB, err := b.GetObject(ctx, cosignedCheckpointProbe)
	if err != nil {
		t.Fatalf("B GetObject: %v", err)
	}
	if string(gotA) != "A horizon" {
		t.Errorf("A's horizon was CLOBBERED: got %q, want %q", gotA, "A horizon")
	}
	if string(gotB) != "B horizon" {
		t.Errorf("B's horizon was CLOBBERED: got %q, want %q", gotB, "B horizon")
	}
}
