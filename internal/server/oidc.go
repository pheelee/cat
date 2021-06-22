package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OidcWorkflow struct{}

func (wf *OidcWorkflow) index(w http.ResponseWriter, r *http.Request) {
	renderIndex(w, r, &templateData{Workflow: "oidc"})
}

func (wf *OidcWorkflow) parseInput(u url.Values) *oidcData {
	return &oidcData{
		ProviderURL:  template.HTMLEscapeString(u.Get("provider")),
		RedirectURL:  template.HTMLEscapeString(u.Get("redir")),
		AppID:        template.HTMLEscapeString(u.Get("app")),
		ClientSecret: template.HTMLEscapeString(u.Get("secret")),
		Scope:        template.HTMLEscapeString(u.Get("scope")),
		AuthFlow:     template.HTMLEscapeString(u.Get("flow")),
	}
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
	s.Expires = time.Now().Add(Sessions.Lifetime)
	s.Provider = provider
	s.Config = &config
	s.State = RandomString(16)
	s.OAuthCodeOpts = append(s.OAuthCodeOpts, oauth2.SetAuthURLParam("response_type", "code"))
	if userInput.AuthFlow == "implicit" {
		s.OAuthCodeOpts = append(s.OAuthCodeOpts, oauth2.SetAuthURLParam("response_type", "id_token token"))
	}
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

	r.ParseForm()
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
		t, err := s.Config.Exchange(context.Background(), code)
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
	var data oidcData
	if raw_access != "" {
		data.AccessToken = PrettyToken(strings.Split(raw_access, ".")[1])
	}
	data.IDToken = PrettyToken(strings.Split(raw_id, ".")[1])
	b, _ := json.MarshalIndent(userinfo, "", "    ")
	data.UserInfo = string(b)
	renderIndex(w, r, &templateData{OidcData: data})
}

func (wf *OidcWorkflow) callbackUrl(r *http.Request) string {
	if r.URL.Scheme == "" {
		if r.Header.Get("X-Forwarded-Proto") != "" {
			r.URL.Scheme = r.Header.Get("X-Forwarded-Proto")
		}
	}
	return fmt.Sprintf("%s://%s/oidc/callback", r.URL.Scheme, r.Host)
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
