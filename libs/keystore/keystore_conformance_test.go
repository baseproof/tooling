/*
FILE PATH: libs/keystore/keystore_conformance_test.go

DESCRIPTION:

	Drives the cross-backend conformance suite against the in-memory
	backend. The vault and pkcs11 packages call the same suite from
	their own test files (with their own backend's New).
*/
package keystore

import "testing"

func TestMemoryKeyStore_Conformance(t *testing.T) {
	RunSecp256k1Conformance(t, NewMemoryKeyStore())
}
