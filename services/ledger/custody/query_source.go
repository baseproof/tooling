package custody

import (
	"context"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/store/indexes"
)

// QuerySource projects the custody chain from on-log entries via the QueryAPI.
// The custody root (ArtifactGenesis), the BP-ENTRY-ARTIFACT-CUSTODY-TRANSFER-V1
// links, and the BP-ENTRY-ARTIFACT-DESTRUCTION-V1 records are each tagged with a
// network-chosen schema_ref (env-configured, like the governance amendment
// kinds). This scans each by schema_ref, decodes, filters to the served
// artifact's ContentDigest, and stamps EffectivePos from each entry's on-log
// Position — exactly the input storage.ArtifactCustodyAt walks.
//
// The entry_index has no ContentDigest column, so per-content selection is an
// in-memory filter over the schema_ref scan (the same shape the governance
// amendment sources use). Cache at the resolver layer if the scan cost matters.
type QuerySource struct {
	q                 *indexes.PostgresQueryAPI
	genesisSchema     types.LogPosition
	transferSchema    types.LogPosition
	destructionSchema types.LogPosition
}

// NewQuerySource wires the projection. genesisSchema is required (the custody
// root); transferSchema / destructionSchema may be null (a network with no
// transfers/destruction yet) — those scans are then skipped.
func NewQuerySource(q *indexes.PostgresQueryAPI, genesisSchema, transferSchema, destructionSchema types.LogPosition) *QuerySource {
	return &QuerySource{
		q:                 q,
		genesisSchema:     genesisSchema,
		transferSchema:    transferSchema,
		destructionSchema: destructionSchema,
	}
}

// Chain implements ChainSource.
func (s *QuerySource) Chain(_ context.Context, servedCID storage.CID) (Chain, error) {
	// 1) Genesis: the ArtifactGenesis whose ArtifactCID == servedCID (or, for
	//    public content where the bytes ARE the plaintext, ContentDigest ==
	//    servedCID). It carries the genesis owner + the ContentDigest custody binds to.
	gEntries, err := s.q.QueryBySchemaRef(s.genesisSchema)
	if err != nil {
		return Chain{}, err
	}
	var (
		genesis storage.ArtifactCustodyRecord
		content storage.CID
		found   bool
	)
	for i := range gEntries {
		e, derr := envelope.Deserialize(gEntries[i].CanonicalBytes)
		if derr != nil {
			continue
		}
		g, derr := storage.DecodeArtifactGenesisPayload(e.DomainPayload)
		if derr != nil {
			continue
		}
		if g.ArtifactCID.Equal(servedCID) || (!g.ContentDigest.IsZero() && g.ContentDigest.Equal(servedCID)) {
			genesis = storage.CustodyGenesisFromArtifactGenesis(g, gEntries[i].Position)
			content = genesis.ContentDigest
			found = true
			break
		}
	}
	if !found {
		return Chain{Found: false}, nil
	}

	transfers, err := s.transfersFor(content)
	if err != nil {
		return Chain{}, err
	}
	destruction, err := s.destructionFor(content)
	if err != nil {
		return Chain{}, err
	}
	return Chain{Genesis: genesis, Transfers: transfers, Destruction: destruction, Found: true}, nil
}

func (s *QuerySource) transfersFor(content storage.CID) ([]storage.ArtifactCustodyTransfer, error) {
	if s.transferSchema.IsNull() {
		return nil, nil
	}
	entries, err := s.q.QueryBySchemaRef(s.transferSchema)
	if err != nil {
		return nil, err
	}
	var out []storage.ArtifactCustodyTransfer
	for i := range entries {
		e, derr := envelope.Deserialize(entries[i].CanonicalBytes)
		if derr != nil {
			continue
		}
		t, derr := storage.DecodeArtifactCustodyTransferPayload(e.DomainPayload)
		if derr != nil || !t.ContentDigest.Equal(content) {
			continue
		}
		t.EffectivePos = entries[i].Position // authority is where the entry landed
		out = append(out, t)
	}
	return out, nil
}

func (s *QuerySource) destructionFor(content storage.CID) (*storage.ArtifactDestruction, error) {
	if s.destructionSchema.IsNull() {
		return nil, nil
	}
	entries, err := s.q.QueryBySchemaRef(s.destructionSchema)
	if err != nil {
		return nil, err
	}
	var earliest *storage.ArtifactDestruction
	for i := range entries {
		e, derr := envelope.Deserialize(entries[i].CanonicalBytes)
		if derr != nil {
			continue
		}
		d, derr := storage.DecodeArtifactDestructionPayload(e.DomainPayload)
		if derr != nil || !d.ContentDigest.Equal(content) {
			continue
		}
		d.EffectivePos = entries[i].Position
		if earliest == nil || d.EffectivePos.Less(earliest.EffectivePos) {
			rec := d
			earliest = &rec
		}
	}
	return earliest, nil
}

// compile-time guard: QuerySource is a ChainSource.
var _ ChainSource = (*QuerySource)(nil)
