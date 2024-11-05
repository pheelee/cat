package session

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	sm, err := NewManager(zerolog.Nop(), time.Hour, "/tmp/session.yaml")
	require.NoError(t, err)
	require.NotNil(t, sm)
	assert.NotNil(t, sm.Sessions)
	assert.Equal(t, time.Hour, sm.Config.Expiration)
	assert.Equal(t, "/tmp/session.yaml", sm.Config.Filepath)
	// Test existing file
	f, err := os.CreateTemp("", "")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	require.NoError(t, os.WriteFile(f.Name(), []byte("{}"), 0600))
	require.NoError(t, f.Close())
	sm, err = NewManager(zerolog.Nop(), time.Hour, f.Name())
	require.NoError(t, err)
	require.NotNil(t, sm)
	assert.NotNil(t, sm.Sessions)
	assert.Equal(t, time.Hour, sm.Config.Expiration)
	assert.Equal(t, f.Name(), sm.Config.Filepath)
}

func TestSessionValid(t *testing.T) {
	s := Session{}
	assert.False(t, s.Valid())
	s = Session{
		Expires: time.Now().Add(time.Hour),
	}
	assert.True(t, s.Valid())
}

func TestNewSession(t *testing.T) {
	sm, err := NewManager(zerolog.Nop(), time.Hour, "/tmp/session.yaml")
	require.NoError(t, err)
	require.NotNil(t, sm)
	s, _ := sm.New("1.2.3.4")
	require.NotNil(t, s)
	assert.Len(t, sm.Sessions, 1)
	assert.Equal(t, s.ID, sm.Sessions[s.ID[:8]].ID)
}

func TestGetSession(t *testing.T) {
	sm := sessionManager{
		Config:   sessionConfig{Expiration: time.Hour},
		Sessions: map[string]*Session{"testtest": {ID: "testtest", Expires: time.Now().Add(time.Hour)}, "testtes2": {ID: "testtes2", Expires: time.Now().Add(time.Hour)}},
	}
	s := sm.Get("testtest")
	require.NotNil(t, s)
	assert.Equal(t, "testtest", s.ID)
	s2 := sm.Get("testtes3")
	require.Nil(t, s2)
	// Test Get with session key longer than 8 characters
	s3 := sm.Get("testtestdeadbeef")
	require.NotNil(t, s3)
	assert.Equal(t, "testtest", s3.ID)
}

func TestOnAppShutdown(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	sm, err := NewManager(zerolog.Nop(), time.Hour, dir+"/session.yaml")
	require.NoError(t, err)
	exp := time.Now().Add(time.Hour)
	sm.Sessions["testtest"] = &Session{
		ID:      "testtest",
		Expires: exp,
	}
	require.NoError(t, sm.OnAppShutdown())
	_, err = os.ReadFile(dir + "/session.yaml")
	require.NoError(t, err)
}

func TestMiddleware(t *testing.T) {
	req, res := httptest.NewRequest("GET", "/", nil), httptest.NewRecorder()
	s := Session{
		ID:      "testtest",
		Expires: time.Now().Add(time.Hour),
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
	sm := sessionManager{
		Config:   sessionConfig{Expiration: time.Hour},
		Sessions: map[string]*Session{"testtest": &s},
	}
	sm.Middleware(next).ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)
	// Test that cookie is written into the response
	assert.Contains(t, res.Header().Get("Set-Cookie"), string(SessionKey))
	// Test that cookie is read from the request
	req, res = httptest.NewRequest("GET", "/", nil), httptest.NewRecorder()
	req.AddCookie(&http.Cookie{
		Name:  string(SessionKey),
		Value: "testtest",
	})
	sm.Middleware(next).ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)

	// Test metadata endpoint
	req, res = httptest.NewRequest("GET", "/api/saml/testtest/metadata", nil), httptest.NewRecorder()
	sm.Middleware(next).ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)
	// Test metadata endpoint with invalid session
	req, res = httptest.NewRequest("GET", "/api/saml/testtes2/metadata", nil), httptest.NewRecorder()
	sm.Middleware(next).ServeHTTP(res, req)
	assert.Equal(t, http.StatusNotFound, res.Code)
}