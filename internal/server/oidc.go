package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	mrand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OidcWorkflow struct{}

func (wf *OidcWorkflow) index(w http.ResponseWriter, r *http.Request) {
	renderIndex(w, r, &templateData{Workflow: "oidc"})
}

func (wf *OidcWorkflow) parseInput(u url.Values) *oidcData {
	d := &oidcData{
		ProviderURL:  template.HTMLEscapeString(u.Get("provider")),
		RedirectURL:  template.HTMLEscapeString(u.Get("redir")),
		AppID:        template.HTMLEscapeString(u.Get("app")),
		ClientSecret: template.HTMLEscapeString(u.Get("secret")),
		Scope:        template.HTMLEscapeString(u.Get("scope")),
		PKCE:         u.Get("pkce") == "on",
	}
	responseType := []string{}
	for _, r := range []string{"code", "token", "id_token"} {
		v := template.HTMLEscapeString(u.Get(r))
		if v == "on" {
			responseType = append(responseType, r)
		}
	}
	d.ResponseType = strings.Join(responseType, " ")
	return d
}

func (wf *OidcWorkflow) setup(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		provider  *oidc.Provider
		config    oauth2.Config
		userInput *oidcData
	)

	ctx := context.Background()

	// Validate input
	if err = r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	userInput = wfOidc.parseInput(r.Form)

	provider, err = oidc.NewProvider(ctx, userInput.ProviderURL)
	if err != nil {
		renderIndex(w, r, &templateData{Error: "oidc - NewProvider - " + template.HTMLEscapeString(err.Error())})
		return
	}

	config = oauth2.Config{
		ClientID:     userInput.AppID,
		ClientSecret: userInput.ClientSecret,
		RedirectURL:  wfOidc.callbackUrl(r),
		Endpoint:     provider.Endpoint(),
		Scopes:       strings.Split(userInput.Scope, " "),
	}
	s := r.Context().Value(sessKey).(*Session)
	s.Expires = time.Now().Add(cfg.SessionLifetime)
	s.Provider = provider
	s.Config = &config
	s.State = RandomString(16)
	if userInput.PKCE {
		s.OIDCVerifier = NewVerifier(128)
		s.OAuthCodeOpts = append(s.OAuthCodeOpts, oauth2.SetAuthURLParam("code_challenge", s.OIDCVerifier.CodeSHA256Challenge()))
		s.OAuthCodeOpts = append(s.OAuthCodeOpts, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	} else {
		s.OIDCVerifier = nil
		s.OAuthCodeOpts = []oauth2.AuthCodeOption{}
	}
	s.OAuthCodeOpts = append(s.OAuthCodeOpts, oauth2.SetAuthURLParam("response_type", userInput.ResponseType))
	s.OAuthCodeOpts = append(s.OAuthCodeOpts, oauth2.SetAuthURLParam("nonce", s.State))
	s.OAuthCodeOpts = append(s.OAuthCodeOpts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	http.Redirect(w, r, config.AuthCodeURL(s.State, s.OAuthCodeOpts...), http.StatusFound)
}

func (wf *OidcWorkflow) restart(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(sessKey).(*Session)
	s.State = RandomString(16)
	http.Redirect(w, r, s.Config.AuthCodeURL(s.State, s.OAuthCodeOpts...), http.StatusFound)
}

func (wf *OidcWorkflow) callback(w http.ResponseWriter, r *http.Request) {

	if err := r.ParseForm(); err != nil {
		renderIndex(w, r, &templateData{Error: err.Error()})
		return
	}
	e := r.FormValue("error")
	if e != "" {
		ed, _ := url.QueryUnescape(r.FormValue("error_description"))
		renderIndex(w, r, &templateData{Error: fmt.Sprintf("error: %s<br>error_description: %s", e, ed)})
		return
	}

	//TODO: Build for POST requests another function
	s := GetSession(r)
	if s == nil {
		renderIndex(w, r, &templateData{Error: "Session not found"})
		return
	}

	code := r.FormValue("code")
	state := r.FormValue("state")

	if s.State != state {
		renderIndex(w, r, &templateData{Error: "invalid state"})
		return
	}

	// if the flow is implicit
	var raw_id, raw_access string
	var userinfo *oidc.UserInfo
	if code != "" {
		opts := []oauth2.AuthCodeOption{}
		if s.OIDCVerifier != nil {
			opts = append(opts, oauth2.SetAuthURLParam("code_verifier", s.OIDCVerifier.Value))
		}
		t, err := s.Config.Exchange(context.Background(), code, opts...)
		if err != nil {
			renderIndex(w, r, &templateData{Error: err.Error()})
			return
		}
		raw_id = t.Extra("id_token").(string)
		raw_access = t.AccessToken
		// call Userinfo endpoint
		userinfo, err = s.Provider.UserInfo(context.Background(), oauth2.StaticTokenSource(t))
		if err != nil {
			fmt.Print(err)
		}
	} else {
		raw_id = r.FormValue("id_token")
		raw_access = r.FormValue("access_token")
	}
	var data oidcData = oidcData{
		RawAccessToken: raw_access,
		RawIDToken:     raw_id,
	}
	// Auth0 issues opaque access tokens used for the userinfo endpoint authentication
	// https://auth0.com/docs/tokens/access-tokens#opaque-access-tokens
	if raw_access != "" && strings.Contains(raw_access, ".") {
		data.AccessToken = PrettyToken(strings.Split(raw_access, ".")[1])
	}
	if raw_id != "" {
		data.IDToken = PrettyToken(strings.Split(raw_id, ".")[1])
	}

	b, _ := json.MarshalIndent(userinfo, "", "    ")
	data.UserInfo = string(b)
	renderIndex(w, r, &templateData{OidcData: data})
}

func (wf *OidcWorkflow) callbackUrl(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/oidc/callback", scheme, r.Host)
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

type Verifier struct {
	Value string
}

func (v Verifier) CodeSHA256Challenge() string {
	h := sha256.New()
	h.Write([]byte(v.Value))
	return base64UrlEncode(h.Sum(nil))
}

func base64UrlEncode(b []byte) string {
	encoded := base64.StdEncoding.EncodeToString(b)
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	encoded = strings.Replace(encoded, "=", "", -1)
	return encoded
}

func NewVerifier(length int) *Verifier {
	upperChars := []rune{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'}
	lowerChars := []rune{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'M', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'}
	specialChars := []rune{'-', ',', '_', '~'}
	chars := upperChars
	chars = append(chars, lowerChars...)
	chars = append(chars, specialChars...)

	b := make([]byte, length)
	m := mrand.New(mrand.NewSource(time.Now().UnixNano())) //#nosec G404
	for i := 0; i < length; i++ {
		b[i] = byte(chars[m.Intn(len(chars))])
	}

	return &Verifier{
		Value: base64UrlEncode(b),
	}
}
