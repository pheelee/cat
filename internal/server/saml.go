package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/pheelee/Cat/pkg/cert"
)

type SamlWorkflow struct{}

var samlMw *samlsp.Middleware

type Map map[string]interface{}

func (wf *SamlWorkflow) setup(w http.ResponseWriter, r *http.Request) {
	var err error
	r.ParseForm()
	mdurl := r.Form.Get("metadata")
	if mdurl == "" {
		renderError(w, r, "metadata parameter missing")
		return
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = r.Header.Get("X-Forwarded-Proto")
	}

	samlMw, err = setupSaml(cfg.Certificate, fmt.Sprintf("%s://%s", scheme, r.Host), mdurl)
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	h.Write([]byte(mdurl + cfg.CookieSecret))
	hash := hex.EncodeToString(h.Sum(nil))
	s := Session{
		Added:  time.Now(),
		SamlMw: samlMw,
		HtmlData: templateData{
			SamlData: samlData{
				IDPMetadataURL: mdurl,
				SPMetadataURL:  fmt.Sprintf("%s/%s", samlMw.ServiceProvider.MetadataURL.String(), hash),
			},
		},
	}
	Sessions.Add(hash, s)
	c := http.Cookie{
		Name:     string(sessKey),
		Value:    hash,
		Path:     "/",
		Expires:  time.Now().Add(Sessions.Lifetime),
		HttpOnly: true,
		Secure:   true,
		Domain:   r.URL.Host,
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, &c)
	http.SetCookie(w, &http.Cookie{Name: "token", MaxAge: -1, Path: "/", HttpOnly: true, Domain: r.Host})
	renderIndex(w, r, s.HtmlData)
}

func setupSaml(cert *cert.Certificate, rootUrl string, metadataUrl string) (*samlsp.Middleware, error) {
	url, err := url.Parse(rootUrl)
	if err != nil {
		return nil, err
	}
	// Fetch Metadata
	idpMd, err := url.Parse(metadataUrl)
	if err != nil {
		return nil, err
	}
	meta, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMd)
	if err != nil {
		return nil, err
	}
	sp, err := samlsp.New(samlsp.Options{
		URL:         *url,
		Key:         cert.PrivteKey,
		Certificate: cert.Cert,
		IDPMetadata: meta,
	})

	if err != nil {
		return nil, err
	}

	return sp, nil
}

func (wf *SamlWorkflow) metadata(w http.ResponseWriter, r *http.Request) {
	rex := regexp.MustCompile(`/saml/metadata/([a-zA-Z0-9]{64})$`)
	m := rex.FindStringSubmatch(r.URL.Path)
	if len(m) > 1 && m[1] != "" {
		r.URL.Path = "/saml/metadata"
		s := Sessions.Get(m[1])
		if s == nil {
			renderError(w, r, "Session not found")
			return
		}
		s.SamlMw.ServeHTTP(w, r)
		return

	}
}

func (wf *SamlWorkflow) callback(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(sessKey).(*Session)
	samlSession, err := s.SamlMw.Session.GetSession(r)
	if err != nil {
		s.SamlMw.HandleStartAuthFlow(w, r)
		return
	}
	//r.WithContext(samlsp.ContextWithSession(r.Context(), samlSession))
	jwtSessionClaims, ok := samlSession.(samlsp.JWTSessionClaims)
	if !ok {
		fmt.Print("could not decode JWT")
	}
	b, err := json.MarshalIndent(jwtSessionClaims, "", "  ")
	if err == nil {
		s.HtmlData.SamlData.Token = string(b)
		s.HtmlData.SamlData.Step = 1
		renderIndex(w, r, s.HtmlData)
	}
}
