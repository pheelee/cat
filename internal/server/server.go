package server

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"text/template"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pheelee/Cat/pkg/cert"
)

var VERSION string
var wfSaml SamlWorkflow
var wfOidc OidcWorkflow
var cfg *Config

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
	Error    string
	OidcData oidcData
	SamlData samlData
	Version  string
}

type oidcData struct {
	Step         int
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
	Step           int
	IDPMetadataURL string
	SPMetadataURL  string
	Token          string
}

func RandomString(n int) string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

func PrettyToken(t string) string {
	b, err := base64.RawStdEncoding.DecodeString(t)
	if err != nil {
		return ""
	}
	var o map[string]interface{}
	err = json.Unmarshal(b, &o)
	if err != nil {
		return ""
	}
	b, _ = json.MarshalIndent(o, "", "    ")
	return string(b)
}

func redirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}

func renderIndex(w http.ResponseWriter, r *http.Request, h templateData) {
	var tpl *template.Template
	if cfg.StaticDir != "" {
		tpl = template.Must(template.ParseFiles(cfg.StaticDir + "/index.html"))
	} else {
		tpl = template.Must(template.ParseFS(f, "index.html"))
	}
	// TODO: merge here with existing session data?
	h.OidcData.RedirectURL = wfOidc.callbackUrl(r)
	h.Version = VERSION
	tpl.Execute(w, h)
}

func renderError(w http.ResponseWriter, r *http.Request, e string) {
	d := templateData{OidcData: oidcData{Step: 1}, SamlData: samlData{Step: 1}, Error: e}
	renderIndex(w, r, d)
}

func requireSession(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(string(sessKey))
		if err != nil {
			renderError(w, r, "Invalid Session Cookie")
			return
		}
		s := Sessions.Get(c.Value)
		if s == nil {
			renderError(w, r, "Session not found")
			return
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

	var fs http.Handler
	cfg = c
	root := mux.NewRouter()
	saml := root.PathPrefix("/saml/").Subrouter()

	saml.Handle("/callback", requireSession(wfSaml.callback)).Methods("POST", "GET")
	saml.Handle("/acs", requireSession(func(w http.ResponseWriter, r *http.Request) {
		r.Context().Value(sessKey).(*Session).SamlMw.ServeHTTP(w, r)
	}))
	saml.Handle("/setup", http.HandlerFunc(wfSaml.setup))
	saml.HandleFunc("/restart", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "token", MaxAge: -1, Path: "/", HttpOnly: true, Domain: r.Host})
		http.Redirect(w, r, "/saml/callback", http.StatusTemporaryRedirect)
	})
	saml.PathPrefix("/metadata/").HandlerFunc(wfSaml.metadata)
	oauth := root.PathPrefix("/oauth").Subrouter()
	oauth.HandleFunc("/setup", wfOidc.setup).Methods("POST")
	oauth.HandleFunc("/setup", redirectHome).Methods("GET")
	oauth.Handle("/callback", requireSession(wfOidc.callback)).Methods("POST")
	oauth.HandleFunc("/callback", redirectHome).Methods("GET")
	if cfg.StaticDir != "" {
		fs = http.FileServer(http.Dir(cfg.StaticDir))
	} else {
		fs = http.FileServer(http.FS(f))
	}

	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		d := templateData{OidcData: oidcData{Step: 0, Scope: "openid", AuthFlow: "code"}}
		s := GetSession(r)
		if s != nil {
			d = s.HtmlData
		}
		renderIndex(w, r, d)
	})
	root.PathPrefix("/").Handler(fs)
	root.Use(handlers.RecoveryHandler())
	return handlers.CombinedLoggingHandler(os.Stdout, proxyRemoteAddr(root))
}
