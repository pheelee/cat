package server

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/go-xmlfmt/xmlfmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
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
	StaticDir    string
	CookieSecret string
	Certificate  *cert.Certificate
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
	ProviderURL  string
	RedirectURL  string
	AppID        string
	ClientSecret string
	Scope        string
	AccessToken  string
	IDToken      string
	UserInfo     string
	AuthFlow     string
}

type samlData struct {
	IDPMetadataURL string
	SPMetadataURL  string
	Token          string
	Certificate    string
	CertRaw        string
}

func RandomString(n int) string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

func RandomHash() string {
	var b []byte = make([]byte, 32)
	rand.Read(b)
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
	tpl.Execute(w, d)
}

func verifyCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
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
				Expires: time.Now().Add(Sessions.Lifetime),
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
				Expires:  time.Now().Add(Sessions.Lifetime),
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

func proxyRemoteAddr(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := r.Header.Get("X-FORWARDED-FOR")
		if a != "" {
			p := strings.Split(a, " ")
			r.RemoteAddr = p[len(p)-1]
		}
		next.ServeHTTP(w, r)
	})
}

func SetupRoutes(c *Config) http.Handler {
	go RunSessionCleanup()
	rateLimit = rlimit.New(5, time.Second*5)
	var fs http.Handler
	cfg = c
	root := mux.NewRouter()

	samlRouter := root.PathPrefix("/saml").Subrouter()
	samlRouter.HandleFunc("", wfSaml.index).Methods("GET")
	samlRouter.Handle("/callback", requireSamlSetup(wfSaml.callback)).Methods("POST", "GET")
	samlRouter.Handle("/acs", requireSamlSetup(func(w http.ResponseWriter, r *http.Request) {
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
	samlRouter.Handle("/setup", verifyCSRF(http.HandlerFunc(wfSaml.setup)))
	samlRouter.HandleFunc("/restart", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "token", MaxAge: -1, Path: "/", HttpOnly: true, Domain: r.Host})
		http.Redirect(w, r, "/saml/callback", http.StatusTemporaryRedirect)
	})
	samlRouter.PathPrefix("/metadata/").HandlerFunc(wfSaml.metadata)
	samlRouter.Use(rateLimit.Limit)
	samlRouter.Use(session)
	oidcRouter := root.PathPrefix("/oidc").Subrouter()
	oidcRouter.HandleFunc("", wfOidc.index).Methods("GET")
	oidcRouter.Handle("/setup", verifyCSRF(http.HandlerFunc(wfOidc.setup))).Methods("POST")
	oidcRouter.HandleFunc("/setup", redirectHome).Methods("GET")
	oidcRouter.Handle("/restart", requireOidcSetup(wfOidc.restart)).Methods("GET")
	oidcRouter.Handle("/callback", requireOidcSetup(wfOidc.callback)).Methods("POST")
	oidcRouter.HandleFunc("/callback", redirectHome).Methods()
	oidcRouter.Use(rateLimit.Limit)
	oidcRouter.Use(session)
	if cfg.StaticDir != "" {
		fs = http.FileServer(http.Dir(cfg.StaticDir))
	} else {
		fs = http.FileServer(http.FS(f))
	}

	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/oidc", http.StatusFound)
	})
	root.PathPrefix("/").Handler(fs)
	root.Use(handlers.RecoveryHandler())
	return handlers.CombinedLoggingHandler(os.Stdout, proxyRemoteAddr(root))
}
