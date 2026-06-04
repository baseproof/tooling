package main

import "testing"

// TestValidateMTLSRequired pins the secure-by-default listener gate: a plaintext
// listener is refused by DEFAULT (the ledger never serves clear text by
// accident); LEDGER_ALLOW_PLAINTEXT is the only opt-out.
func TestValidateMTLSRequired(t *testing.T) {
	const tlsCert = "/run/certs/server.crt"
	cases := []struct {
		name           string
		allowPlaintext bool
		tlsCertFile    string
		wantErr        bool
	}{
		{"plaintext listener, not allowed → fail closed (the default)", false, "", true},
		{"plaintext listener, explicitly allowed → ok (proxy/loopback opt-out)", true, "", false},
		{"mTLS listener → ok", false, tlsCert, false},
		{"mTLS listener + allow → ok (allow is a no-op when already TLS)", true, tlsCert, false},
	}
	for _, tc := range cases {
		err := validateMTLSRequired(tc.allowPlaintext, tc.tlsCertFile)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}
