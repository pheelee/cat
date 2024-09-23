package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml/samlsp"
	"github.com/pheelee/Cat/pkg/cert"
	"golang.org/x/oauth2"
)

type Session struct {
	Expires      time.Time           `json:"expires"`
	Certificates []*cert.Certificate `json:"certificates"`

	Provider      *oidc.Provider          `json:"-"`
	Config        *oauth2.Config          `json:"-"`
	OIDCVerifier  *Verifier               `json:"-"`
	OAuthCodeOpts []oauth2.AuthCodeOption `json:"-"`
	SamlMw        *samlsp.Middleware      `json:"-"`
	SamlOpts      SamlOpts                `json:"-"`
	State         string                  `json:"-"`
	CsrfToken     string                  `json:"-"`
}

type SessionManager struct {
	sync.Mutex
	filePath string
	Items    map[string]*Session `json:"sessions"`
}

func (m *SessionManager) Save() error {
	b, _ := json.MarshalIndent(m.Items, "", "  ")
	return os.WriteFile(path.Clean(m.filePath), b, 0600)
}

func LoadSessionManager(filepath string) (*SessionManager, error) {
	sm := &SessionManager{
		filePath: filepath,
		Mutex:    sync.Mutex{},
		Items:    map[string]*Session{},
	}
	b, err := os.ReadFile(path.Clean(filepath))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err != nil && os.IsNotExist(err) {
		return sm, nil
	}
	return sm, json.Unmarshal(b, &sm.Items)
}

func (m *SessionManager) New() (*Session, error) {
	id := randomHash()
	crt, err := cert.Generate(id, "IRBE", "CH", "IT", cfg.SessionLifetime.String())
	if err != nil {
		return nil, err
	}
	m.Items[id] = &Session{
		Expires:      time.Now().Add(cfg.SessionLifetime),
		Certificates: []*cert.Certificate{crt},
	}

	return m.Items[id], nil
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

func (m *SessionManager) RunSessionCleanup(shutdown <-chan struct{}, routines *sync.WaitGroup) {
	routines.Add(1)
	defer routines.Done()
	t := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-t.C:
			now := time.Now()
			for h, s := range m.Items {
				if now.After(s.Expires) {
					m.Remove(h)
				}
			}
		case <-shutdown:
			if err := m.Save(); err != nil {
				fmt.Println(err)
			}
			return
		}
	}
}

func randomHash() string {
	var b []byte = make([]byte, 32)
	_, _ = rand.Read(b)
	h := sha256.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
