/*
FILE PATH: libs/keystore/vault/vault_conformance_test.go

DESCRIPTION:

	Drives the cross-backend conformance suite (defined in
	api/exchange/keystore/conformance.go) against the Vault Transit
	backend. Identical assertions as the MemoryKeyStore run, so wire
	shapes are guaranteed interchangeable.
*/
package vault

import (
	"testing"

	"github.com/baseproof/tooling/libs/keystore"
)

func TestVault_Conformance(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	keystore.RunSecp256k1Conformance(t, ks)
}
