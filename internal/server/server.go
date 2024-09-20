package server

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-xmlfmt/xmlfmt"
	"github.com/grantae/certinfo"
	"github.com/pheelee/Cat/pkg/cert"
	"github.com/pheelee/Cat/pkg/rlimit"
)

var VERSION string
var wfSaml SamlWorkflow
var wfOidc OidcWorkflow
var cfg *Config
var rateLimit *rlimit.RateLimit

//go:embed *
var f embed.FS

type sessionKey string

const sessKey sessionKey = "session"

// Config holds the servers configurtion parameters
type Config struct {
	StaticDir       string
	CookieSecret    string
	Certificate     *cert.Certificate
	SessionLifetime time.Duration
}

type templateData struct {
	Workflow  string
	Step      int
	CsrfToken string
	Error     string
	OidcData  oidcData
	SamlData  samlData
	Version   string
}

type oidcData struct {
	ProviderURL    string
	RedirectURL    string
	AppID          string
	ClientSecret   string
	Scope          string
	AccessToken    string
	IDToken        string
	RawAccessToken string
	RawIDToken     string
	UserInfo       string
	ResponseType   string
	PKCE           bool
}

type samlData struct {
	IDPMetadataURL    string
	SPMetadataURL     string
	Token             string
	Certificate       string
	CertRaw           string
	SetupInstructions []setupInstruction
}

type setupInstruction struct {
	Title   string
	Content string
}

func RandomString(n int) string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))] // #nosec G404
	}
	return string(b)
}

func RandomHash() string {
	var b []byte = make([]byte, 32)
	_, _ = crand.Read(b)
	h := sha256.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func redirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}

func renderIndex(w http.ResponseWriter, r *http.Request, d *templateData) {
	var tpl *template.Template
	if cfg.StaticDir != "" {
		tpl = template.Must(template.ParseFiles(cfg.StaticDir + "/index.html"))
	} else {
		tpl = template.Must(template.ParseFS(f, "index.html"))
	}
	p := strings.Split(r.URL.Path, "/")
	d.CsrfToken = RandomHash()
	d.Version = VERSION
	d.Workflow = p[1]
	if len(p) > 2 && p[2] == "callback" {
		d.Step = 1
	}
	s := r.Context().Value(sessKey).(*Session)
	s.CsrfToken = d.CsrfToken
	c, err := certinfo.CertificateText(cfg.Certificate.Cert)
	if err != nil {
		d.SamlData.Certificate = err.Error()
	} else {
		d.SamlData.Certificate = c
	}
	d.SamlData.CertRaw = string(cfg.Certificate.CertPEM)

	w.Header().Set("X-Frame-Options", "deny")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	if err := tpl.Execute(w, d); err != nil {
		log.Printf("ERROR: %s", err)
	}
}

func verifyCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			log.Printf("ERROR: %s", err)
		}
		s := r.Context().Value(sessKey).(*Session)
		if s.CsrfToken == "" || r.Form.Get("csrf_token") != s.CsrfToken {
			renderIndex(w, r, &templateData{Error: "Invalid CSRF Token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireSamlSetup(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := r.Context().Value(sessKey).(*Session)
		if s.SamlMw == nil {
			renderIndex(w, r, &templateData{Error: "Setup SAML service provider first"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireOidcSetup(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := r.Context().Value(sessKey).(*Session)
		if s.Config == nil || s.Provider == nil {
			renderIndex(w, r, &templateData{Error: "Setup OIDC service provider first"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := GetSession(r)
		if s == nil || !s.Valid() {
			s = &Session{
				Expires: time.Now().Add(cfg.SessionLifetime),
			}
			id := RandomHash()
			Sessions.Add(s, id)
			ssite := http.SameSiteDefaultMode
			if r.Header.Get("X-Forwarded-Proto") == "https" {
				ssite = http.SameSiteNoneMode
			}
			c := http.Cookie{
				Name:     string(sessKey),
				Value:    id,
				Path:     "/",
				Expires:  time.Now().Add(cfg.SessionLifetime),
				HttpOnly: true,
				Secure:   r.Header.Get("X-Forwarded-Proto") == "https",
				Domain:   r.URL.Host,
				SameSite: ssite,
			}
			http.SetCookie(w, &c)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessKey, s)))
	})
}

func SetupRoutes(c *Config, shutdown <-chan struct{}, routines *sync.WaitGroup) http.Handler {
	go RunSessionCleanup(shutdown, routines)
	rateLimit = rlimit.New(5, time.Second*5)
	var fs http.Handler
	cfg = c
	root := chi.NewRouter()
	root.Use(middleware.RealIP)
	root.Use(middleware.Logger)
	root.Use(middleware.Recoverer)
	root.Route("/saml", func(r chi.Router) {
		r.Use(rateLimit.Limit)
		r.Use(session)
		r.Get("/", wfSaml.index)
		r.Get("/callback", requireSamlSetup(wfSaml.callback).ServeHTTP)
		r.Post("/callback", requireSamlSetup(wfSaml.callback).ServeHTTP)
		r.Handle("/acs", requireSamlSetup(func(w http.ResponseWriter, r *http.Request) {
			// Attach our custom error handler
			var m *samlsp.Middleware = r.Context().Value(sessKey).(*Session).SamlMw
			m.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
				if parseErr, ok := err.(*saml.InvalidResponseError); ok {
					renderIndex(w, r, &templateData{Error: fmt.Sprintf("<pre class='xml'>%s</pre> <br><br>Now: %s %s",
						strings.Replace(xmlfmt.FormatXML(parseErr.Response, "", "  "), "<", "&lt;", -1), parseErr.Now, parseErr.PrivateErr)})
				} else {
					log.Printf("ERROR: %s", err)
				}
			}
			m.ServeHTTP(w, r)
		}))
		r.Handle("/slo", requireSamlSetup(func(w http.ResponseWriter, r *http.Request) {
			//TODO: does this work for idp initiated single logout where no session is available?
			var m *samlsp.Middleware = r.Context().Value(sessKey).(*Session).SamlMw
			m.ServeHTTP(w, r)
		}))
		r.Handle("/setup", verifyCSRF(http.HandlerFunc(wfSaml.setup)))
		r.HandleFunc("/restart", func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "token", MaxAge: -1, Path: "/", HttpOnly: true, Domain: r.Host})
			http.Redirect(w, r, "/saml/callback", http.StatusTemporaryRedirect)
		})
		r.HandleFunc("/metadata/*", wfSaml.metadata)
	})

	root.Route("/oidc", func(r chi.Router) {
		r.Use(rateLimit.Limit)
		r.Use(session)
		r.Get("/", wfOidc.index)
		r.Post("/setup", verifyCSRF(http.HandlerFunc(wfOidc.setup)).ServeHTTP)
		r.Get("/setup", redirectHome)
		r.Get("/restart", requireOidcSetup(wfOidc.restart).ServeHTTP)
		r.Post("/callback", requireOidcSetup(wfOidc.callback).ServeHTTP)
		r.Get("/callback", redirectHome)
	})

	if cfg.StaticDir != "" {
		fs = http.FileServer(http.Dir(cfg.StaticDir))
	} else {
		fs = http.FileServer(http.FS(f))
	}

	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/oidc", http.StatusFound)
	})
	root.Get("/*", fs.ServeHTTP)
	return root
}
