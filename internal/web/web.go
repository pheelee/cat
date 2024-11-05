package web

import (
	"context"
	"embed"
	"encoding/json"
	"encoding/xml"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/go-chi/chi/v5"
	"github.com/pheelee/Cat/internal/session"
	"github.com/pheelee/Cat/pkg/pkce"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

//go:embed dist/*
var assets embed.FS

var logger zerolog.Logger

type userInfo struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error().Err(err).Msg("json encode error")
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func jsonError(w http.ResponseWriter, status int, err error) {
	w.WriteHeader(status)
	jsonResponse(w, map[string]string{"error": err.Error()})
}

func userinfo(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(session.SessionKey).(*session.Session)
	jsonResponse(w, userInfo{
		ID:      s.ID[:8],
		Expires: s.Expires,
	})
}

func getSamlConfig(w http.ResponseWriter, r *http.Request) {
	var err error
	s := r.Context().Value(session.SessionKey).(*session.Session)
	if s.SAMLSP == nil {
		s.SAMLSP, err = samlsp.New(samlsp.Options{
			EntityID: s.SAMLConfig.SPEntityID,

			DefaultRedirectURI: "/saml?step=3",
			Key:                s.SAMLConfig.Certificates.Primary.PrivateKey,
			Certificate:        s.SAMLConfig.Certificates.Primary.Cert,
			AllowIDPInitiated:  s.SAMLConfig.AllowIdpInitiated,
			SignRequest:        s.SAMLConfig.RequestSigning,
		})
		if err != nil {
			logger.Error().Err(err).Msg("new samlsp error")
			jsonError(w, http.StatusBadRequest, err)
			return
		}
		origin := referrerHost(r)
		s.SAMLConfig.SPMetadataUrl = origin + "/api/saml/" + s.ID[:8] + "/metadata"
		s.SAMLConfig.NameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	}
	jsonResponse(w, s.SAMLConfig)
}

func putSamlConfig(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(session.SessionKey).(*session.Session)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error().Err(err).Msg("read body error")
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	defer r.Body.Close()
	//TODO: validate user input!
	var req session.SamlParams
	if err := json.Unmarshal(b, &req); err != nil {
		logger.Error().Err(err).Msg("json decode error")
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	req.Certificates.Primary = s.SAMLConfig.Certificates.Primary
	req.Certificates.Secondary = s.SAMLConfig.Certificates.Secondary
	s.SAMLConfig = req
	if s.SAMLConfig.IdpMetadata == "" && s.SAMLConfig.IdpUrl != "" {
		c := http.Client{Timeout: 5 * time.Second}
		res, err := c.Get(s.SAMLConfig.IdpUrl)
		if err != nil {
			logger.Error().Err(err).Msg("get idp metadata error")
			jsonError(w, http.StatusBadRequest, err)
			return
		}
		defer res.Body.Close()
		b, err = io.ReadAll(res.Body)
		if err != nil {
			logger.Error().Err(err).Msg("read idp metadata error")
			jsonError(w, http.StatusBadRequest, err)
			return
		}
		s.SAMLConfig.IdpMetadata = string(b)
	}
	var metadata *saml.EntityDescriptor
	if s.SAMLConfig.IdpMetadata != "" {
		metadata, err = samlsp.ParseMetadata([]byte(s.SAMLConfig.IdpMetadata))
		if err != nil {
			logger.Error().Err(err).Msg("parse idp metadata error")
			jsonError(w, http.StatusBadRequest, err)
			return
		}
	}
	origin := referrerHost(r)
	u, _ := url.Parse(origin)
	if s.SAMLSP, err = samlsp.New(samlsp.Options{
		EntityID:           s.SAMLConfig.SPEntityID,
		DefaultRedirectURI: "/saml?step=3",
		URL:                *u,
		IDPMetadata:        metadata,
		Key:                s.SAMLConfig.Certificates.Primary.PrivateKey,
		Certificate:        s.SAMLConfig.Certificates.Primary.Cert,
		AllowIDPInitiated:  s.SAMLConfig.AllowIdpInitiated,
		SignRequest:        s.SAMLConfig.RequestSigning,
	}); err != nil {
		logger.Error().Err(err).Msg("new samlsp error")
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	if u, err = url.Parse(origin + "/api/saml/" + s.ID[:8] + "/acs"); err != nil {
		logger.Error().Err(err).Msg("parse acs url error")
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	s.SAMLSP.ServiceProvider.AcsURL = *u
	s.SAMLSP.ServiceProvider.AuthnNameIDFormat = saml.NameIDFormat(s.SAMLConfig.NameIdFormat)
	s.SAMLSP.ServiceProvider.SignatureMethod = s.SAMLConfig.RequestSigningAlgo

	jsonResponse(w, s.SAMLConfig)
}

func samlCallback(w http.ResponseWriter, r *http.Request) {
	var err error
	// After the assertion was consumed, the user is redirected back here
	s := r.Context().Value(session.SessionKey).(*session.Session)
	if s.SAMLConfig.Assertion, err = s.SAMLSP.Session.GetSession(r); err != nil {
		s.SAMLSP.HandleStartAuthFlow(w, r)
		return
	}
	http.Redirect(w, r, "/saml?step=3", http.StatusSeeOther)
}

func samlMetadata(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(session.SessionKey).(*session.Session)
	data := s.SAMLSP.ServiceProvider.Metadata()
	if !s.SAMLConfig.AddEncryptionCert {
		for i, s := range data.SPSSODescriptors {
			var kd []saml.KeyDescriptor
			for _, p := range s.SSODescriptor.RoleDescriptor.KeyDescriptors {
				if p.Use != "encryption" {
					kd = append(kd, p)
				}
			}
			data.SPSSODescriptors[i].SSODescriptor.RoleDescriptor.KeyDescriptors = kd
		}
	}
	w.Header().Set("Content-Disposition", "attachment; filename=cat-"+s.ID[:8]+"-metadata.xml")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if err := xml.NewEncoder(w).Encode(data); err != nil {
		logger.Error().Err(err).Msg("xml encode error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func samlAcs(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(session.SessionKey).(*session.Session)
	s.SAMLSP.ServeACS(w, r)
}

func getOidcConfig(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(session.SessionKey).(*session.Session)
	s.OIDCConfig.RedirectURI = referrerHost(r) + "/api/oidc/" + s.ID[:8] + "/callback"
	jsonResponse(w, s.OIDCConfig)
}

func putOidcConfig(w http.ResponseWriter, r *http.Request) {
	var err error
	s := r.Context().Value(session.SessionKey).(*session.Session)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error().Err(err).Msg("read body error")
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	defer r.Body.Close()
	if err := json.Unmarshal(b, &s.OIDCConfig); err != nil {
		logger.Error().Err(err).Msg("json unmarshal error")
		jsonError(w, http.StatusBadRequest, err)
		return
	}

	if s.OIDCConfig.MetadataUrl != "" {
		// We read the issuer from the metadata document and use that to setup the oidc provider
		res, err := http.Get(s.OIDCConfig.MetadataUrl)
		if err != nil {
			logger.Error().Err(err).Msg("get oidc metadata error")
			jsonError(w, http.StatusBadRequest, err)
			return
		}
		defer res.Body.Close()
		type Metadata struct {
			Issuer string `json:"issuer"`
		}
		var metadata Metadata
		if err := json.NewDecoder(res.Body).Decode(&metadata); err != nil {
			logger.Error().Err(err).Msg("decode oidc metadata error")
			jsonError(w, http.StatusBadRequest, err)
			return
		}
		if s.OIDCClient.Provider, err = oidc.NewProvider(context.Background(), metadata.Issuer); err != nil {
			logger.Error().Err(err).Msg("new oidc provider error")
			jsonError(w, http.StatusBadRequest, err)
			return
		}
		s.OIDCClient.Config = oauth2.Config{
			ClientID:     s.OIDCConfig.ClientID,
			ClientSecret: s.OIDCConfig.Secret,
			RedirectURL:  s.OIDCConfig.RedirectURI,
			Endpoint:     s.OIDCClient.Provider.Endpoint(),
			Scopes:       s.OIDCConfig.Scopes,
		}
	}
	jsonResponse(w, s.OIDCConfig)
}

func oidcStart(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(session.SessionKey).(*session.Session)
	// Clear error
	s.OIDCConfig.ErrorResponse.Error = ""
	options := []oauth2.AuthCodeOption{}
	var response_type []string
	if s.OIDCConfig.ResponseType.Code {
		response_type = append(response_type, "code")
	}
	if s.OIDCConfig.ResponseType.Token {
		response_type = append(response_type, "token")
	}
	if s.OIDCConfig.ResponseType.IDToken {
		response_type = append(response_type, "id_token")
	}
	if s.OIDCConfig.PKCE {
		s.OIDCConfig.PKCEData = pkce.NewPKCE(43)
		options = append(options, oauth2.SetAuthURLParam("code_challenge", s.OIDCConfig.PKCEData.CodeChallenge))
		options = append(options, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	options = append(options, oauth2.SetAuthURLParam("response_type", strings.Join(response_type, " ")))
	s.OIDCClient.Nonce = randomString(8)
	options = append(options, oauth2.SetAuthURLParam("nonce", s.OIDCClient.Nonce))
	//TODO: add more response modes
	options = append(options, oauth2.SetAuthURLParam("response_mode", "form_post"))
	http.Redirect(w, r, s.OIDCClient.Config.AuthCodeURL(s.OIDCClient.Nonce, options...), http.StatusFound)

}
func oidcCallback(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(session.SessionKey).(*session.Session)
	// Empty tokens
	s.OIDCConfig.Tokens = session.Tokens{}
	if err := r.ParseForm(); err != nil {
		logger.Error().Err(err).Msg("parse form error")
		s.OIDCConfig.ErrorResponse.Error = err.Error()
		http.Redirect(w, r, "/oidc?step=1", http.StatusSeeOther)
		return
	}
	if s.OIDCClient.Nonce != r.Form.Get("state") {
		logger.Error().Str("nonce", s.OIDCClient.Nonce).Str("state", r.Form.Get("state")).Msg("invalid state")
		s.OIDCConfig.ErrorResponse.Error = "invalid state"
		http.Redirect(w, r, "/oidc?step=1", http.StatusSeeOther)
		return
	}

	// for Entra ID the following fields are set error, error_description, error_uri
	// Example Entra ID:
	// error: unsupported_response_type
	// error_description: AADSTS700054: response_type 'id_token' is not enabled for the application. Trace ID: 17968c03-61ff-4fdb-9e63-de1e8dcf1b00 Correlation ID: ca83068b-cd02-4394-b242-68949f047333 Timestamp: 2024-10-03 17:25:35Z
	// error_uri: https://login.microsoftonline.com/error?code=700054
	//
	// for Auth0 the error page of the IdP is shown and the user is not redirected back to our application
	//
	// for Keycloak the following fields are set error, error_description and iss
	// Example Keycloak:
	// error: unauthorized_client
	// error_description: Client is not allowed to initiate browser login with given response_type. Implicit flow is disabled for the client.
	// iss: https://sts.irbe.ch/realms/irbe

	if r.Form.Get("error") != "" {
		logger.Error().Str("error", r.Form.Get("error")).Str("error_description", r.Form.Get("error_description")).Msg("IdP returns error")
		s.OIDCConfig.ErrorResponse.Error = r.Form.Get("error")
		s.OIDCConfig.ErrorResponse.Description = r.Form.Get("error_description")
		http.Redirect(w, r, "/oidc?step=1", http.StatusSeeOther)
		return
	}

	if r.Form.Get("code") != "" {
		// Authorization code flow

		// handle PKCE
		options := []oauth2.AuthCodeOption{}
		if s.OIDCConfig.PKCEData != nil {
			options = append(options, oauth2.SetAuthURLParam("code_verifier", s.OIDCConfig.PKCEData.CodeVerifier))
		}

		t, err := s.OIDCClient.Config.Exchange(context.Background(), r.Form.Get("code"), options...)
		if err != nil {
			logger.Error().Err(err).Msg("exchange code error")
			s.OIDCConfig.ErrorResponse.Error = err.Error()
			http.Redirect(w, r, "/oidc?step=1", http.StatusSeeOther)
			return
		}
		s.OIDCConfig.Tokens = session.Tokens{
			AccessToken: t.AccessToken,
			IDToken:     t.Extra("id_token").(string),
		}
	} else {
		// Implicit flow
		s.OIDCConfig.Tokens = session.Tokens{
			AccessToken: r.Form.Get("access_token"),
			IDToken:     r.Form.Get("id_token"),
		}
	}
	http.Redirect(w, r, "/oidc?step=1", http.StatusSeeOther)
}

func randomString(n int) string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))] // #nosec G404
	}
	return string(b)
}

func referrerHost(r *http.Request) string {
	p := strings.Split(r.Header.Get("Referer"), "/")
	return strings.Join(p[:3], "/")
}

func GetRouter(log zerolog.Logger, sessionExpiration time.Duration, middlewares ...func(http.Handler) http.Handler) *chi.Mux {
	logger = log
	r := chi.NewRouter()
	r.Use(middlewares...)
	r.Route("/api", func(r chi.Router) {
		r.Get("/userinfo", userinfo)
		r.Route("/saml", func(r chi.Router) {
			r.Get("/", getSamlConfig)
			r.Put("/", putSamlConfig)
			r.HandleFunc("/callback", samlCallback)
			r.Get("/{id}/metadata", samlMetadata)
			r.HandleFunc("/{id}/acs", samlAcs)
		})
		r.Route("/oidc", func(r chi.Router) {
			r.Get("/", getOidcConfig)
			r.Put("/", putOidcConfig)
			r.Post("/start", oidcStart)
			r.Post("/{id}/callback", oidcCallback)
		})

	})

	// route everyting else to the index.html of the embedded fs
	r.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		fSub, _ := fs.Sub(assets, "dist")
		if strings.HasPrefix(r.URL.Path, "/assets") || strings.HasPrefix(r.URL.Path, "/favicon.ico") {
			http.FileServer(http.FS(fSub)).ServeHTTP(w, r)
			return
		}
		f, _ := fSub.Open("index.html")
		defer f.Close()
		b, _ := io.ReadAll(f)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		_, _ = w.Write(b)
	})
	return r
}