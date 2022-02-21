package server

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/pheelee/Cat/pkg/cert"
)

type SamlWorkflow struct {
}

type SamlOpts struct {
	MetadataURL             string
	MetadataFile            []byte
	SignRequest             bool
	SignAlgorithm           string
	NameIDFormat            string
	NoEncryptionCertificate bool
	AllowIDPInitiated       bool
}

func (wf *SamlWorkflow) parseOpts(r *http.Request) SamlOpts {
	r.ParseForm()
	return SamlOpts{
		MetadataFile:            []byte(r.FormValue("metadatafile")),
		MetadataURL:             r.FormValue("metadata"),
		SignRequest:             r.FormValue("signRequest") == "on",
		SignAlgorithm:           r.FormValue("sigAlg"),
		NameIDFormat:            r.FormValue("nameIDFormat"),
		NoEncryptionCertificate: r.FormValue("NoEncryptionCertificate") == "on",
		AllowIDPInitiated:       r.FormValue("AllowIDPInitiated") == "on",
	}
}

func (wf *SamlWorkflow) index(w http.ResponseWriter, r *http.Request) {
	renderIndex(w, r, &templateData{Workflow: "saml"})
}

func (wf *SamlWorkflow) setup(w http.ResponseWriter, r *http.Request) {
	var samlMw *samlsp.Middleware
	var err error
	o := wf.parseOpts(r)
	if len(o.MetadataURL) == 0 && len(o.MetadataFile) == 0 {
		renderIndex(w, r, &templateData{})
		return
	}
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}

	samlMw, err = setupSaml(cfg.Certificate, fmt.Sprintf("%s://%s", scheme, r.Host), o)
	if err != nil {
		renderIndex(w, r, &templateData{Error: fmt.Sprintf("Could not setup SAML Service Provider<br>%s", err)})
		return
	}
	s := r.Context().Value(sessKey).(*Session)
	s.SamlOpts = o
	s.Expires = time.Now().Add(Sessions.Lifetime)
	s.SamlMw = samlMw
	c, err := r.Cookie(string(sessKey))
	if err != nil {
		renderIndex(w, r, &templateData{Error: "Cookie not found"})
		return
	}
	d := samlData{
		IDPMetadataURL: o.MetadataURL,
		SPMetadataURL:  fmt.Sprintf("%s/%s", samlMw.ServiceProvider.MetadataURL.String(), c.Value),
		SetupInstructions: []setupInstruction{{
			Title: "AzureAD config with Powershell",
			Content: fmt.Sprintf(`$app = New-AzureADApplication -DisplayName "Cat-saml" -IdentifierUris "%s" -SamlMetadataUrl "%s" -ReplyUrls "%s";New-AzureADServicePrincipal -DisplayName "Cat-saml" -AccountEnabled $true -AppId $app.AppId -AppRoleAssignmentRequired $false  -Tags "WindowsAzureActiveDirectoryIntegratedApp","WindowsAzureActiveDirectoryCustomSingleSignOnApplication"`,
				samlMw.ServiceProvider.MetadataURL.String(),
				fmt.Sprintf("%s/%s", samlMw.ServiceProvider.MetadataURL.String(), c.Value),
				samlMw.ServiceProvider.AcsURL.String(),
			),
		}},
	}
	http.SetCookie(w, &http.Cookie{Name: "token", MaxAge: -1, Path: "/", HttpOnly: true, Domain: r.Host})
	renderIndex(w, r, &templateData{SamlData: d})
}

func setupSaml(cert *cert.Certificate, rootUrl string, o SamlOpts) (*samlsp.Middleware, error) {
	url, err := url.Parse(rootUrl)
	if err != nil {
		return nil, fmt.Errorf("setupSaml - parse root url - %s", err)
	}
	// Fetch Metadata or parse uploaded file
	var meta *saml.EntityDescriptor
	if o.MetadataURL != "" {
		idpMd, err := url.Parse(o.MetadataURL)
		if err != nil {
			return nil, fmt.Errorf("setupSaml - parse metadata url - %s", err)
		}
		meta, err = samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMd)
		if err != nil {
			return nil, fmt.Errorf("setupSaml - idp fetch metadata - %s", err)
		}
	} else {
		meta, err = samlsp.ParseMetadata(o.MetadataFile)
		if err != nil {
			return nil, fmt.Errorf("setupSaml - idp parse metadata - %s", err)
		}
	}

	sp, err := samlsp.New(samlsp.Options{
		URL:                *url,
		Key:                cert.PrivteKey,
		Certificate:        cert.Cert,
		IDPMetadata:        meta,
		SignRequest:        o.SignRequest,
		AllowIDPInitiated:  o.AllowIDPInitiated,
		DefaultRedirectURI: "/saml/callback",
	})
	sp.ServiceProvider.AuthnNameIDFormat = saml.NameIDFormat(o.NameIDFormat)
	sp.ServiceProvider.SignatureMethod = o.SignAlgorithm

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
		d := s.SamlMw.ServiceProvider.Metadata()
		if s.SamlOpts.NoEncryptionCertificate {
			for i, s := range d.SPSSODescriptors {
				var kd []saml.KeyDescriptor
				for _, p := range s.SSODescriptor.RoleDescriptor.KeyDescriptors {
					if p.Use != "encryption" {
						kd = append(kd, p)
					}
				}
				d.SPSSODescriptors[i].SSODescriptor.RoleDescriptor.KeyDescriptors = kd
			}
		}
		buf, _ := xml.MarshalIndent(d, "", "  ")
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Write(buf)
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
