package pkce

import "testing"

func TestGenerateCodeVerifier(t *testing.T) {
	verifier := generateCodeVerifier(43)
	if len(verifier) != 43 {
		t.Fatalf("expected %d, got %d", 43, len(verifier))
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	challenge := generateCodeChallenge("ThisIs43ByteLongStringWhichIsUsedForRFC7636")
	if len(challenge) != 43 {
		t.Fatalf("expected %d, got %d", 43, len(challenge))
	}
	if challenge != "1aK9sWh_gVVn2-kahkyOG9b27gnC1kp2x2QwvvBmvBE" {
		t.Fatalf("expected %s, got %s", "1aK9sWh_gVVn2-kahkyOG9b27gnC1kp2x2QwvvBmvBE", challenge)
	}
}

func TestNewPKCE(t *testing.T) {
	pkce := NewPKCE(43)
	if len(pkce.CodeVerifier) != 43 {
		t.Fatalf("expected %d, got %d", 43, len(pkce.CodeVerifier))
	}
	if len(pkce.CodeChallenge) != 43 {
		t.Fatalf("expected %d, got %d", 43, len(pkce.CodeChallenge))
	}
}
