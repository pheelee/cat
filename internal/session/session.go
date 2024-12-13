package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml/samlsp"
	"github.com/pheelee/Cat/pkg/cert"
	"github.com/pheelee/Cat/pkg/pkce"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type keySession string

var (
	SessionKey     = keySession("cat-session")
	anonymousPaths = regexp.MustCompile(`^/api/(saml|oidc)/([a-zA-Z0-9]{8})/metadata$`)
)

type errorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

type SamlParams struct {
	IdpUrl             string        `json:"idp_url" yaml:"idp_url"`
	SPEntityID         string        `json:"sp_entity_id" yaml:"sp_entity_id"`
	SPMetadataUrl      string        `json:"sp_metadata_url" yaml:"sp_metadata_url"`
	IdpMetadata        string        `json:"idp_metadata" yaml:"-"`
	RequestSigning     bool          `json:"request_signing" yaml:"request_signing"`
	RequestSigningAlgo string        `json:"request_signing_algo" yaml:"request_signing_algo"`
	AddEncryptionCert  bool          `json:"add_encryption_cert" yaml:"add_encryption_cert"`
	AllowIdpInitiated  bool          `json:"allow_idp_initiated" yaml:"allow_idp_initiated"`
	NameIdFormat       string        `json:"name_id_format" yaml:"name_id_format"`
	Certificates       certificates  `json:"certificates" yaml:"certificates"`
	ActiveCert         string        `json:"active_cert" yaml:"active_cert"`
	ErrorResponse      errorResponse `json:"error_response" yaml:"-"`
}

type OidcParams struct {
	MetadataUrl   string        `json:"metadata_url" yaml:"metadata_url"`
	PublicClient  bool          `json:"public_client" yaml:"public_client"`
	PKCE          bool          `json:"pkce" yaml:"pkce"`
	PKCEData      *pkce.PKCE    `json:"-" yaml:"-"`
	ResponseType  responseType  `json:"response_type" yaml:"response_type"`
	ClientID      string        `json:"client_id" yaml:"client_id"`
	Secret        string        `json:"secret" yaml:"secret"`
	RedirectURI   string        `json:"redirect_uri" yaml:"redirect_uri"`
	Scopes        []string      `json:"scopes" yaml:"scopes"`
	ErrorResponse errorResponse `json:"error_response" yaml:"-"`
}

type responseType struct {
	Code    bool `json:"code" yaml:"code"`
	Token   bool `json:"token" yaml:"token"`
	IDToken bool `json:"id_token" yaml:"id_token"`
}

type sessionConfig struct {
	Expiration time.Duration
	Filepath   string
	logger     zerolog.Logger
}

type Session struct {
	ID         string             `json:"id" yaml:"id"`
	Shared     bool               `json:"shared" yaml:"shared"`
	JIT        JIT                `json:"jit" yaml:"jit"`
	Expires    time.Time          `json:"expires" yaml:"expires"`
	SAMLConfig SamlParams         `json:"saml,omitempty" yaml:"saml,omitempty"`
	OIDCConfig OidcParams         `json:"oidc,omitempty" yaml:"oidc,omitempty"`
	SAMLSP     *samlsp.Middleware `json:"-" yaml:"-"`
	OIDCClient oidcClient         `json:"-" yaml:"-"`
}

type oidcClient struct {
	Provider *oidc.Provider
	Config   oauth2.Config
	Nonce    string
}

type certificates struct {
	Primary   *cert.Certificate `json:"primary" yaml:"primary"`
	Secondary *cert.Certificate `json:"secondary" yaml:"secondary"`
}

// Valid returns true if the session has not expired, false otherwise.
func (s *Session) Valid() bool {
	return time.Now().Before(s.Expires)
}

type sessionManager struct {
	Config   sessionConfig
	Sessions map[string]*Session `json:"sessions" yaml:"sessions"`
}

// NewManager creates a new sessionManager with the given logger, expiration
// duration, and file path. It loads the active sessions from the given file
// path, and returns an error if the file does not exist or if there is an
// error loading the sessions.
func NewManager(logger zerolog.Logger, expiration time.Duration, filePath string) (*sessionManager, error) {
	sm := sessionManager{
		Config: sessionConfig{
			Expiration: expiration,
			Filepath:   filePath,
			logger:     logger.With().Str("component", "sessionManager").Logger(),
		},
		Sessions: map[string]*Session{},
	}
	b, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err != nil && os.IsNotExist(err) {
		return &sm, nil
	}
	return &sm, yaml.Unmarshal(b, &sm.Sessions)
}

// New creates a new session with a random 16 byte hex string as its ID,
// and sets its expiration time to the current time plus the session
// manager's expiration duration. The new session is stored in the session
// manager's map of active sessions and returned.
func (s *sessionManager) New(ip string, sessId string) (*Session, error) {
	sharedSession := sessId != ""
	expiration := time.Now().Add(time.Hour * 24 * 365)
	if sessId == "" {
		var id = make([]byte, 16)
		_, _ = rand.Read(id)
		sessId = hex.EncodeToString(id)
		expiration = time.Now().Add(s.Config.Expiration)
	}
	primaryCert, err := cert.Generate("cat-tokensigner-"+sessId[:8]+"-primary", "IRBE", "CH", "IT", s.Config.Expiration.String())
	if err != nil {
		s.Config.logger.Error().Err(err).Msg("failed to generate primary certificate")
		return nil, err
	}
	secondaryCert, err := cert.Generate("cat-tokensigner-"+sessId[:8]+"-secondary", "IRBE", "CH", "IT", s.Config.Expiration.String())
	if err != nil {
		s.Config.logger.Error().Err(err).Msg("failed to generate secondary certificate")
		return nil, err
	}
	s.Sessions[sessId[:8]] = &Session{
		ID:      sessId,
		Shared:  sharedSession,
		JIT:     JIT{Config: JITConfig{Enabled: false}},
		Expires: expiration,
		SAMLConfig: SamlParams{
			IdpUrl:             "",
			IdpMetadata:        "",
			RequestSigning:     false,
			RequestSigningAlgo: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			AddEncryptionCert:  false,
			AllowIdpInitiated:  true,
			NameIdFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
			Certificates: certificates{
				Primary:   primaryCert,
				Secondary: secondaryCert,
			},
		},
		OIDCConfig: OidcParams{
			MetadataUrl:  "",
			PublicClient: false,
			PKCE:         false,
			ResponseType: responseType{Code: true, Token: false, IDToken: false},
			ClientID:     "",
			Secret:       "",
			RedirectURI:  "",
			Scopes:       []string{"openid"},
		},
	}
	s.Config.logger.Info().Str("ip", ip).Str("id", sessId).Msg("created new session")
	return s.Sessions[sessId[:8]], nil
}

// OnAppShutdown writes the current session state to disk, removing any
// invalid sessions or sessions without SAML or OIDC configuration. It
// marshals the session data into YAML format and writes it to the file
// specified in the session manager's configuration. Returns an error
// if marshaling or writing to the file fails.
func (s *sessionManager) OnAppShutdown() error {
	s.Config.logger.Info().Msg("writing session state to disk")
	for k, se := range s.Sessions {
		if se == nil || !se.Valid() {
			delete(s.Sessions, k)
			continue
		}
		if se.SAMLConfig.IdpUrl == "" && se.OIDCConfig.MetadataUrl == "" {
			delete(s.Sessions, k)
		}
	}
	b, err := yaml.Marshal(s.Sessions)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Clean(s.Config.Filepath), b, 0600)
}

// Get returns the session with the given ID if it exists and is valid,
// otherwise nil is returned.
func (s *sessionManager) Get(key string) *Session {
	if len(key) > 8 {
		key = key[:8]
	}
	se, ok := s.Sessions[key]
	if !ok {
		s.Config.logger.Warn().Str("id", key).Msg("session not found")
		return nil
	}
	return se
}

// Middleware returns an http.Handler that validates the session cookie in the request
// and, if valid, stores the session in the request context. If the cookie is invalid
// or missing, it creates a new session and stores it in the request context.
//
// The session is stored in the request context under the key `sessionKey`.
//
// The middleware also sets the SameSite attribute of the cookie to `SameSiteNoneMode` if
// the request is over HTTPS, and to `SameSiteDefaultMode` otherwise.
func (s sessionManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// first check if we have a session id in the path
		if anonymousPaths.MatchString(r.URL.Path) {
			m := anonymousPaths.FindStringSubmatch(r.URL.Path)
			se := s.Get(m[2])
			if se != nil && se.Valid() {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), SessionKey, se)))
				return
			} else {
				s.Config.logger.Warn().Str("id", m[2]).Str("path", r.URL.Path).Msg("anonymousPath: session not found")
				// TODO: present a beautiful not found page
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("Session not found"))
				return
			}
		}
		ssite := http.SameSiteDefaultMode
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			ssite = http.SameSiteNoneMode
		}
		initiateSharedSession := strings.HasPrefix(r.URL.Path, "/shared/")
		// check if we have a shared session and return that if present
		if initiateSharedSession {
			se := s.Get(strings.Split(r.URL.Path, "/")[2])
			if se == nil || !se.Valid() {
				var err error
				s.Config.logger.Warn().Str("id", strings.Split(r.URL.Path, "/")[2]).Str("path", r.URL.Path).Msg("create new shared session")
				se, err = s.New(r.RemoteAddr, strings.Split(r.URL.Path, "/")[2])
				if err != nil {
					s.Config.logger.Error().Err(err).Msg("failed to create shared session")
					// TODO: present a beautiful error page
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
			// Check if cookie is present otherwise create one
			c, err := r.Cookie(string(SessionKey))
			if err != nil || c.Value != se.ID {
				http.SetCookie(w, &http.Cookie{
					Name:     string(SessionKey),
					Value:    se.ID,
					Path:     "/",
					Expires:  se.Expires,
					HttpOnly: true,
					Secure:   r.Header.Get("X-Forwarded-Proto") == "https",
					Domain:   r.URL.Host,
					SameSite: ssite,
				})
			}
			// Convert to shared session
			if !se.Shared {
				se.Shared = true
				se.Expires = time.Now().Add(time.Hour * 24 * 365)
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), SessionKey, se)))
			return
		}
		c, _ := r.Cookie(string(SessionKey))
		if c != nil {
			if se := s.Get(c.Value); se != nil && se.Valid() {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), SessionKey, se)))
				return
			}
		}
		// get client IP address either from X-Forwarded-For or RemoteAddr
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = strings.Split(r.RemoteAddr, ":")[0]
		}
		se, err := s.New(ip, "")
		if err != nil {
			s.Config.logger.Error().Err(err).Msg("failed to create session")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		c = &http.Cookie{
			Name:     string(SessionKey),
			Value:    se.ID,
			Path:     "/",
			Expires:  se.Expires,
			HttpOnly: true,
			Secure:   r.Header.Get("X-Forwarded-Proto") == "https",
			Domain:   r.URL.Host,
			SameSite: ssite,
		}
		http.SetCookie(w, c)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), SessionKey, se)))
	})
}
