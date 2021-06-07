package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OidcWorkflow struct{}

func (wf *OidcWorkflow) parseInput(u url.Values) templateData {
	return templateData{
		OidcData: oidcData{
			ProviderURL:  u.Get("provider"),
			RedirectURL:  u.Get("redir"),
			AppID:        u.Get("app"),
			ClientSecret: u.Get("secret"),
			Scope:        u.Get("scope"),
			AuthFlow:     u.Get("flow"),
		},
	}
}

func (wf *OidcWorkflow) setup(w http.ResponseWriter, r *http.Request) {
	var (
		err      error
		provider *oidc.Provider
		config   oauth2.Config
		hdat     templateData
	)

	ctx := context.Background()

	// Validate input
	if err = r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hdat = wfOidc.parseInput(r.Form)

	provider, err = oidc.NewProvider(ctx, hdat.OidcData.ProviderURL)
	if err != nil {
		hdat.Error = err.Error()
		renderIndex(w, r, hdat)
		return
	}

	config = oauth2.Config{
		ClientID:     hdat.OidcData.AppID,
		ClientSecret: hdat.OidcData.ClientSecret,
		RedirectURL:  wfOidc.callbackUrl(r),
		Endpoint:     provider.Endpoint(),
		Scopes:       strings.Split(hdat.OidcData.Scope, " "),
	}

	s := Session{
		Added:    time.Now(),
		Provider: provider,
		HtmlData: hdat,
		Config:   config,
		State:    RandomString(16),
	}

	h := sha256.New()
	h.Write([]byte(hdat.OidcData.AppID + hdat.OidcData.ProviderURL + hdat.OidcData.RedirectURL + hdat.OidcData.ClientSecret + cfg.CookieSecret))
	hash := hex.EncodeToString(h.Sum(nil))

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

	response := oauth2.SetAuthURLParam("response_type", "code")
	if s.HtmlData.OidcData.AuthFlow == "implicit" {
		response = oauth2.SetAuthURLParam("response_type", "id_token token")
	}
	nonce := oauth2.SetAuthURLParam("nonce", s.State)
	method := oauth2.SetAuthURLParam("response_mode", "form_post")
	http.SetCookie(w, &c)
	http.Redirect(w, r, config.AuthCodeURL(s.State, response, nonce, method), http.StatusFound)
}

func (wf *OidcWorkflow) callback(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	e := r.FormValue("error")
	if e != "" {
		ed, _ := url.QueryUnescape(r.FormValue("error_description"))
		renderError(w, r, fmt.Sprintf("error: %s<br>error_description: %s", e, ed))
		return
	}

	// get session from cookie
	c, err := r.Cookie(string(sessKey))
	if err != nil {
		renderError(w, r, err.Error())
		return
	}
	//ToDo: Build for POST requests another function
	s := Sessions.Get(c.Value)
	if s == nil {
		renderError(w, r, "Session not found")
		return
	}

	code := r.FormValue("code")
	state := r.FormValue("state")

	if s.State != state {
		renderError(w, r, "invalid state")
		return
	}

	// if the flow is implicit
	var raw_id, raw_access string
	var userinfo *oidc.UserInfo
	switch s.HtmlData.OidcData.AuthFlow {
	case "code":
		t, err := s.Config.Exchange(context.Background(), code)
		if err != nil {
			renderError(w, r, err.Error())
			return
		}
		raw_id = t.Extra("id_token").(string)
		raw_access = t.AccessToken
		// call Userinfo endpoint
		userinfo, err = s.Provider.UserInfo(context.Background(), oauth2.StaticTokenSource(t))
		if err != nil {
			fmt.Print(err)
		}
	case "implicit":
		raw_id = r.FormValue("id_token")
		raw_access = r.FormValue("access_token")
	}

	s.HtmlData.OidcData.Step = 1
	if raw_access != "" {
		s.HtmlData.OidcData.AccessToken = PrettyToken(strings.Split(raw_access, ".")[1])
	}
	s.HtmlData.OidcData.IDToken = PrettyToken(strings.Split(raw_id, ".")[1])
	b, _ := json.MarshalIndent(userinfo, "", "    ")
	s.HtmlData.OidcData.UserInfo = string(b)
	renderIndex(w, r, s.HtmlData)
}

func (wf *OidcWorkflow) callbackUrl(r *http.Request) string {
	if r.URL.Scheme == "" {
		if r.Header.Get("X-Forwarded-Proto") != "" {
			r.URL.Scheme = r.Header.Get("X-Forwarded-Proto")
		}
	}
	return fmt.Sprintf("%s://%s/oauth/callback", r.URL.Scheme, r.Host)
}
