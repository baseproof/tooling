package loadgen

import (
	"math/rand"

	"github.com/baseproof/baseproof/types"
)

// root is one SMT leaf the model tracks while it is still amendable. The signer
// key is NOT stored — it is re-derived from index on demand (see deriveIdentity),
// so a root costs only a handful of words plus its did string.
type root struct {
	index        uint64            // derivation index (stable identity handle)
	pos          types.LogPosition // CREATION position; the SMT key derives from it
	originTipSeq uint64            // advances on each Path-A amendment
	authTipSeq   uint64            // stays at creation (Path A is the origin lane)
	did          string            // self-certifying did:key, kept for the oracle record
}

// amendWindow is a bounded FIFO ring of the most-recently-created roots that are
// still eligible to be amended. It is the working set that makes BOTH memory and
// the streaming oracle bounded:
//
//   - amendments only ever target a root still in the window, so once a root is
//     EVICTED (pushed out by newer roots) no future amendment can change its
//     expected state — its oracle record is final and is streamed out immediately;
//   - capacity K ⇒ at most K live roots regardless of total entries, so the heap
//     is O(K), not O(roots). This is the structural cure for the half of the
//     backfill OOM that was the ever-growing `entities []*entity` slice.
//
// Targeting recent roots is also the realistic end-user shape: amendments cluster
// on recently-created entities far more than on ancient ones.
type amendWindow struct {
	buf  []*root
	head int // ring index of the oldest live root
	n    int // number of live roots (≤ len(buf))
}

func newAmendWindow(capacity int) *amendWindow {
	if capacity < 1 {
		capacity = 1
	}
	return &amendWindow{buf: make([]*root, capacity)}
}

func (w *amendWindow) len() int { return w.n }

// push adds r as the newest root. When the window is already full it evicts and
// RETURNS the oldest root (whose state is now final); otherwise it returns nil.
func (w *amendWindow) push(r *root) *root {
	if w.n < len(w.buf) {
		w.buf[(w.head+w.n)%len(w.buf)] = r
		w.n++
		return nil
	}
	evicted := w.buf[w.head]
	w.buf[w.head] = r
	w.head = (w.head + 1) % len(w.buf)
	return evicted
}

// pick returns a uniformly-random live root, or nil when the window is empty. The
// caller's seeded rng drives selection so the chosen target is reproducible.
func (w *amendWindow) pick(rng *rand.Rand) *root {
	if w.n == 0 {
		return nil
	}
	return w.buf[(w.head+rng.Intn(w.n))%len(w.buf)]
}

// drain returns the remaining live roots oldest→newest and empties the window —
// the end-of-run flush of records that were never evicted.
func (w *amendWindow) drain() []*root {
	out := make([]*root, 0, w.n)
	for i := 0; i < w.n; i++ {
		out = append(out, w.buf[(w.head+i)%len(w.buf)])
	}
	for i := range w.buf {
		w.buf[i] = nil
	}
	w.head, w.n = 0, 0
	return out
}
