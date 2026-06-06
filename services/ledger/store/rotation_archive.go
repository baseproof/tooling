/*
FILE PATH: store/rotation_archive.go

Witness-rotation evolution chain, archived for PG-free reconstruction (1.2b).

WHY: the SDK's bundle.StandaloneGather.FetchWitnessRotationChain returns the
witness-rotation evolution up to a proof's committing head — each element
self-proving (record + inclusion + smt + committing head) so a verifier replays the
set evolution from genesis. The online source assembles it from PG (witness_sets +
tiles); a PG-off read front, or a cold proof, needs it without PG. Rotations are
RARE, so the whole chain is small: we archive it as ONE object and reconstruct the
SDK seam by reading + filtering to the proof's anchor.

Additive + best-effort (cf. 1.1a/1.2a): the archive never gates a rotation; its
absence means "no rotations" (the common case — most networks never rotate), which
is exactly the SDK seam's empty-chain result. []bundle.RotationElement round-trips
losslessly through encoding/json (the proof types are SDK wire types), so the
archive needs no bespoke codec.
*/
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/baseproof/baseproof/log/bundle"
)

// rotationArchiveVersion prefixes the encoded chain so the format can evolve
// without silently misreading an older archive.
const rotationArchiveVersion byte = 1

// rotationChainKey is the LOGICAL object key for the archived witness-rotation
// chain — a single key (the chain is small; rotations are rare). The *bytestore.S3
// adapter prepends the per-log namespace, so two logs sharing a bucket never
// collide. MUST match api/horizon.go rotationChainObject.
func rotationChainKey() string { return "witness-rotations" }

// encodeRotationChain serializes the full chain: a 1-byte version, then JSON of the
// SDK's []RotationElement (lossless — proof fields are SDK wire types).
func encodeRotationChain(chain []bundle.RotationElement) ([]byte, error) {
	body, err := json.Marshal(chain)
	if err != nil {
		return nil, fmt.Errorf("store/rotation-archive: marshal chain: %w", err)
	}
	return append([]byte{rotationArchiveVersion}, body...), nil
}

// decodeRotationChain validates the version and parses the chain. A bad version or
// malformed body is REJECTED (corruption), never silently treated as "no rotations"
// — a damaged archive surfaces as an error the caller maps to a transient fault.
func decodeRotationChain(raw []byte) ([]bundle.RotationElement, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("store/rotation-archive: empty chain blob")
	}
	if raw[0] != rotationArchiveVersion {
		return nil, fmt.Errorf("store/rotation-archive: unsupported version %d (want %d)", raw[0], rotationArchiveVersion)
	}
	var chain []bundle.RotationElement
	if err := json.Unmarshal(raw[1:], &chain); err != nil {
		return nil, fmt.Errorf("store/rotation-archive: decode chain: %w", err)
	}
	return chain, nil
}

// RotationChainReader reads the archived witness-rotation chain blob from the object
// store. os.ErrNotExist when no chain was ever archived (a never-rotated network).
type RotationChainReader interface {
	ReadRotationChain(ctx context.Context) ([]byte, error)
}

// ArchiveRotationChainFetcher satisfies bundle.StandaloneGather's
// FetchWitnessRotationChain PG-free, from the object-store archive.
type ArchiveRotationChainFetcher struct {
	reader RotationChainReader
}

// NewArchiveRotationChainFetcher wires the fetcher to a chain-archive reader.
func NewArchiveRotationChainFetcher(reader RotationChainReader) *ArchiveRotationChainFetcher {
	return &ArchiveRotationChainFetcher{reader: reader}
}

// FetchWitnessRotationChain returns the witness-rotation evolution up to
// asOfTreeSize, each element self-proving, read PG-free. A never-rotated network
// (archive miss) yields the empty chain — the SDK's "no rotations" result. Elements
// are filtered to those whose CommittingHead.TreeSize <= asOfTreeSize, so the chain
// matches the proof's anchor (a rotation committed AFTER the anchor is not part of
// the evolution the proof replays). Order is preserved from the archive.
func (f *ArchiveRotationChainFetcher) FetchWitnessRotationChain(ctx context.Context, asOfTreeSize uint64) ([]bundle.RotationElement, error) {
	raw, err := f.reader.ReadRotationChain(ctx)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // never rotated (or pre-archive) → empty chain
	}
	if err != nil {
		return nil, err
	}
	chain, err := decodeRotationChain(raw)
	if err != nil {
		return nil, err
	}
	var out []bundle.RotationElement
	for _, el := range chain {
		if el.CommittingHead.TreeSize <= asOfTreeSize {
			out = append(out, el)
		}
	}
	return out, nil
}

// RotationChainArchiveWriter durably archives the full witness-rotation chain so the
// fetcher reconstructs it PG-free. Best-effort: the caller (rotation apply) logs a
// write error and never stalls on it; the backfill job (1.x) regenerates it.
type RotationChainArchiveWriter struct {
	obj objectPutGetter
}

// NewRotationChainArchiveWriter wires the writer to the object store. A nil obj makes
// ArchiveRotationChain a no-op, so the composition root can wire it unconditionally.
func NewRotationChainArchiveWriter(obj objectPutGetter) *RotationChainArchiveWriter {
	return &RotationChainArchiveWriter{obj: obj}
}

// ArchiveRotationChain serializes + writes the full chain to the single rotation key.
func (w *RotationChainArchiveWriter) ArchiveRotationChain(ctx context.Context, chain []bundle.RotationElement) error {
	if w == nil || w.obj == nil {
		return nil
	}
	body, err := encodeRotationChain(chain)
	if err != nil {
		return err
	}
	if err := w.obj.PutObject(ctx, rotationChainKey(), body); err != nil {
		return fmt.Errorf("store/rotation-archive: put %s: %w", rotationChainKey(), err)
	}
	return nil
}
