package main

import "testing"

func TestMustAddresses(t *testing.T) {
	got := mustAddresses("0x1111111111111111111111111111111111111111, 2222222222222222222222222222222222222222")
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0][0] != 0x11 || got[1][0] != 0x22 {
		t.Fatalf("parsed wrong: %x %x", got[0][0], got[1][0])
	}
	// Empty CSV → freeze (empty set), not an error.
	if n := len(mustAddresses("")); n != 0 {
		t.Fatalf("empty CSV: len = %d, want 0", n)
	}
	// Stray whitespace / trailing comma tolerated.
	if n := len(mustAddresses(" , 0x3333333333333333333333333333333333333333 ,")); n != 1 {
		t.Fatalf("whitespace CSV: len = %d, want 1", n)
	}
}

func TestMustSchemaPos(t *testing.T) {
	p := mustSchemaPos("did:web:state:tn:davidson@7", "fallback")
	if p.LogDID != "did:web:state:tn:davidson" || p.Sequence != 7 {
		t.Fatalf("got %+v", p)
	}
	// Empty log-did before '@' → fallback (the bootstrap log DID).
	p2 := mustSchemaPos("@9", "fallback-did")
	if p2.LogDID != "fallback-did" || p2.Sequence != 9 {
		t.Fatalf("got %+v", p2)
	}
}

func TestLabels(t *testing.T) {
	if modeLabel("") != "Mode B (PoW)" || modeLabel("tok") != "Mode A (credit)" {
		t.Fatal("modeLabel wrong")
	}
	if addrsLabel(nil) == "" {
		t.Fatal("empty addrsLabel")
	}
	var a [20]byte
	a[0] = 0xab
	if got := addrsLabel([][20]byte{a}); got[0] != '{' || got[len(got)-1] != '}' {
		t.Fatalf("addrsLabel format: %q", got)
	}
}
