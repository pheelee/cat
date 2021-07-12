package server

import (
	"context"
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

func (wf *SamlWorkflow) index(w http.ResponseWriter, r *http.Request) {
	renderIndex(w, r, &templateData{Workflow: "saml"})
}

func (wf *SamlWorkflow) setup(w http.ResponseWriter, r *http.Request) {
	var samlMw *samlsp.Middleware
	var err error
	r.ParseForm()
	mdurl := r.Form.Get("metadata")
	if mdurl == "" {
		renderIndex(w, r, &templateData{})
		return
	}
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}

	samlMw, err = setupSaml(cfg.Certificate, fmt.Sprintf("%s://%s", scheme, r.Host), mdurl)
	if err != nil {
		renderIndex(w, r, &templateData{Error: fmt.Sprintf("Could not setup SAML Service Provider<br>%s", err)})
		return
	}
	s := r.Context().Value(sessKey).(*Session)
	s.Expires = time.Now().Add(Sessions.Lifetime)
	s.SamlMw = samlMw
	c, err := r.Cookie(string(sessKey))
	if err != nil {
		renderIndex(w, r, &templateData{Error: "Cookie not found"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "token", MaxAge: -1, Path: "/", HttpOnly: true, Domain: r.Host})
	renderIndex(w, r, &templateData{SamlData: samlData{
		IDPMetadataURL: mdurl,
		SPMetadataURL:  fmt.Sprintf("%s/%s", samlMw.ServiceProvider.MetadataURL.String(), c.Value),
	}})
}

func setupSaml(cert *cert.Certificate, rootUrl string, metadataUrl string) (*samlsp.Middleware, error) {
	url, err := url.Parse(rootUrl)
	if err != nil {
		return nil, fmt.Errorf("setupSaml - parse root url - %s", err)
	}
	// Fetch Metadata
	idpMd, err := url.Parse(metadataUrl)
	if err != nil {
		return nil, fmt.Errorf("setupSaml - parse metadata url - %s", err)
	}
	meta, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMd)
	if err != nil {
		return nil, fmt.Errorf("setupSaml - idp fetch metadata - %s", err)
	}
	sp, err := samlsp.New(samlsp.Options{
		URL:         *url,
		Key:         cert.PrivteKey,
		Certificate: cert.Cert,
		IDPMetadata: meta,
	})

	if err != nil {
		return nil, fmt.Errorf("setupSaml - samlSp.new - %s", err)
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
			renderIndex(w, r, &templateData{Error: "Session not found"})
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
		renderIndex(w, r, &templateData{SamlData: samlData{Token: string(b)}})
		return
	}
	renderIndex(w, r, &templateData{Error: err.Error()})
}
