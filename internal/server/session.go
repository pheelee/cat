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

var Sessions SessionMap = SessionMap{
	Lifetime: 12 * time.Hour,
	Items:    map[string]Session{},
}

type Session struct {
	Added    time.Time
	Provider *oidc.Provider
	Config   oauth2.Config
	SamlMw   *samlsp.Middleware
	HtmlData templateData
	State    string
}

type SessionMap struct {
	sync.Mutex
	Lifetime time.Duration
	Items    map[string]Session
}

func GetSession(r *http.Request) *Session {
	c, err := r.Cookie(string(sessKey))
	if err != nil {
		return nil
	}
	return Sessions.Get(c.Value)
}

func (s *SessionMap) Add(hash string, sess Session) {
	s.Mutex.Lock()
	s.Items[hash] = sess
	s.Mutex.Unlock()
	fmt.Printf("%s Session added %s\n", time.Now(), hash)
}

func (s *SessionMap) Remove(hash string) {
	s.Mutex.Lock()
	delete(s.Items, hash)
	s.Mutex.Unlock()
	fmt.Printf("%s Session deleted %s\n", time.Now(), hash)
}

func (sm *SessionMap) Get(hash string) *Session {
	s, ok := sm.Items[hash]
	if ok {
		return &s
	}
	return nil
}

func RunSessionCleanup() {
	for {
		if shutdown {
			break
		}
		now := time.Now()
		for h, s := range Sessions.Items {
			if now.After(s.Added.Add(Sessions.Lifetime)) {
				Sessions.Remove(h)
			}
		}
		time.Sleep(30 * time.Second)
	}

}
