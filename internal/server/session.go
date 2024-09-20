package server

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml/samlsp"
	"github.com/pheelee/Cat/pkg/cert"
	"golang.org/x/oauth2"
)

var Sessions SessionManager = SessionManager{
	Items: map[string]*Session{},
}

type Session struct {
	Expires      time.Time
	PrivateKey   *rsa.PrivateKey
	Certificates map[string]*cert.Certificate

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
	Items map[string]*Session
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

func RunSessionCleanup(shutdown <-chan struct{}, routines *sync.WaitGroup) {
	routines.Add(1)
	defer routines.Done()
	t := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-t.C:
			now := time.Now()
			for h, s := range Sessions.Items {
				if now.After(s.Expires) {
					Sessions.Remove(h)
				}
			}
		case <-shutdown:
			return
		}
	}
}
