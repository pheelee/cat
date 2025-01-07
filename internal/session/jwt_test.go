package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestJWT(t *testing.T) {
	s := Session{
		ID:      "test",
		Expires: time.Now().Add(time.Hour),
		manager: &sessionManager{Config: sessionConfig{Secret: "secret"}},
	}
	jwt, err := s.GenerateJWT()
	require.NoError(t, err)
	require.True(t, s.ValidateJWT(jwt))

	// Test expired token
	s.Expires = time.Now().Add(-time.Hour)
	jwt, err = s.GenerateJWT()
	require.NoError(t, err)
	require.False(t, s.ValidateJWT(jwt))
}
