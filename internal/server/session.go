package server

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/crewjam/saml/samlsp"
	"golang.org/x/oauth2"
)

var shutdown bool = false

var Sessions SessionManager = SessionManager{
	Lifetime: 12 * time.Hour,
	Items:    map[string]*Session{},
}

type Session struct {
	Expires       time.Time
	Provider      *oidc.Provider
	Config        *oauth2.Config
	OIDCVerifier  *Verifier
	OAuthCodeOpts []oauth2.AuthCodeOption
	SamlMw        *samlsp.Middleware
	SamlOpts      SamlOpts
	State         string
	CsrfToken     string
}

type SessionManager struct {
	sync.Mutex
	Lifetime time.Duration
	Items    map[string]*Session
}

func GetSession(r *http.Request) *Session {
	c, err := r.Cookie(string(sessKey))
	if err != nil {
		return nil
	}
	return Sessions.Get(c.Value)
}

func (m *SessionManager) Add(s *Session, hash string) {
	m.Mutex.Lock()
	m.Items[hash] = s
	m.Mutex.Unlock()
	fmt.Printf("%s Session added %s\n", time.Now(), hash)
}

func (m *SessionManager) Remove(hash string) {
	m.Mutex.Lock()
	delete(m.Items, hash)
	m.Mutex.Unlock()
	fmt.Printf("%s Session deleted %s\n", time.Now(), hash)
}

func (m *SessionManager) Get(hash string) *Session {
	s, ok := m.Items[hash]
	if ok {
		return s
	}
	return nil
}

func (s *Session) Valid() bool {
	return time.Now().Before(s.Expires)
}

func RunSessionCleanup() {
	for {
		if shutdown {
			break
		}
		now := time.Now()
		for h, s := range Sessions.Items {
			if now.After(s.Expires) {
				Sessions.Remove(h)
			}
		}
		time.Sleep(30 * time.Second)
	}

}
