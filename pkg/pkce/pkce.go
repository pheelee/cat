package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
)

type PKCE struct {
	CodeVerifier  string
	CodeChallenge string
}

// generateCodeVerifier returns a random string of the given length, composed of the
// characters [a-zA-Z0-9-._~]. The string is suitable for use as a PKCE code verifier.
func generateCodeVerifier(length int) string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	verifier := make([]byte, length)
	for i := range verifier {
		verifier[i] = chars[rand.Intn(len(chars))] // #nosec G404
	}
	return string(verifier)
}

// generateCodeChallenge generates a code challenge as per RFC 7636.
//
// The function takes a code verifier as input and returns a code challenge.
// The code challenge is computed by hashing the verifier using SHA256 and
// encoding the result using URL-safe base64 encoding without padding.
func generateCodeChallenge(verifier string) string {
	sha256Hash := sha256.New()
	sha256Hash.Write([]byte(verifier))
	hash := sha256Hash.Sum(nil)

	// Encode the hash using URL-safe base64 encoding without padding
	return base64.RawURLEncoding.EncodeToString(hash)
}

// NewPKCE generates a new PKCE instance, suitable for use as a
// authorization request parameter.
//
// The function takes a single argument, verifierLength, which specifies the
// length of the code verifier to generate. The code verifier is a random
// string of the given length, composed of the characters
// [a-zA-Z0-9-._~]. The function returns a *PKCE instance, which contains
// the generated code verifier and the corresponding code challenge.
func NewPKCE(verifierLength int) *PKCE {
	verifier := generateCodeVerifier(verifierLength)
	challenge := generateCodeChallenge(verifier)
	return &PKCE{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
	}
}
