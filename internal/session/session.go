package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml/samlsp"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/pheelee/Cat/internal/scim2"
	"github.com/pheelee/Cat/pkg/cert"
	"github.com/pheelee/Cat/pkg/pkce"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type keySession string

var (
	SessionKey = keySession("cat-session")
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
	Secret     string
	Filepath   string
	S3         *minio.Client
	S3Bucket   string
	logger     zerolog.Logger
}

type Session struct {
	manager      *sessionManager    `json:"-" yaml:"-"`
	ID           string             `json:"id" yaml:"id"`
	Shared       bool               `json:"shared" yaml:"shared"`
	Provisioning Provisioning       `json:"provisioning" yaml:"provisioning"`
	Expires      time.Time          `json:"expires" yaml:"expires"`
	SAMLConfig   SamlParams         `json:"saml,omitempty" yaml:"saml,omitempty"`
	OIDCConfig   OidcParams         `json:"oidc,omitempty" yaml:"oidc,omitempty"`
	SAMLSP       *samlsp.Middleware `json:"-" yaml:"-"`
	OIDCClient   oidcClient         `json:"-" yaml:"-"`
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

// initS3 checks if the S3_HOST, S3_ACCESS_KEY, S3_ACCESS_SECRET and S3_BUCKET environment variables are set. If they are, it sets up an S3 client and sets sm.Config.S3 to the client.
func (sm *sessionManager) initS3() error {
	var err error
	s3_host := os.Getenv("S3_HOST")
	s3_access_key := os.Getenv("S3_ACCESS_KEY")
	s3_access_secret := os.Getenv("S3_ACCESS_SECRET")
	sm.Config.S3Bucket = os.Getenv("S3_BUCKET")
	if s3_host != "" && s3_access_key != "" && s3_access_secret != "" && sm.Config.S3Bucket != "" {
		sm.Config.logger.Info().Msg("using S3 for session storage")
		sm.Config.S3, err = minio.New(s3_host, &minio.Options{
			Creds:  credentials.NewStaticV4(s3_access_key, s3_access_secret, ""),
			Secure: true,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// NewManager creates a new sessionManager with the given logger, expiration
// duration, and file path. It loads the active sessions from the given file
// path, and returns an error if the file does not exist or if there is an
// error loading the sessions.
func NewManager(logger zerolog.Logger, expiration time.Duration, filePath, secret string) (*sessionManager, error) {
	var (
		b   []byte
		err error
	)
	sm := sessionManager{
		Config: sessionConfig{
			Expiration: expiration,
			Filepath:   filePath,
			logger:     logger.With().Str("component", "sessionManager").Logger(),
			Secret:     secret,
		},
		Sessions: map[string]*Session{},
	}
	if err = sm.initS3(); err != nil {
		return nil, err
	}
	if sm.Config.S3 != nil {
		obj, err := sm.Config.S3.GetObject(context.Background(), sm.Config.S3Bucket, filepath.Base(sm.Config.Filepath), minio.GetObjectOptions{})
		if err != nil {
			return nil, err
		}
		b, err = io.ReadAll(obj)
		if err != nil && err.(minio.ErrorResponse).Code != "NoSuchKey" {
			return nil, err
		}
		if err == nil {
			return &sm, yaml.Unmarshal(b, &sm.Sessions)
		}
	}

	if sm.Config.S3 == nil {
		sm.Config.logger.Info().Msg("using local file for session storage")
	}
	b, err = os.ReadFile(filepath.Clean(filePath))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err != nil && os.IsNotExist(err) {
		return &sm, nil
	}
	// Write file to S3 to complete migration
	if sm.Config.S3 != nil {
		_, err = sm.Config.S3.PutObject(context.Background(), sm.Config.S3Bucket, "sessions.yaml", bytes.NewReader(b), int64(len(b)), minio.PutObjectOptions{
			ContentType: "application/yaml",
		})
		if err != nil {
			return nil, err
		}
	}

	return &sm, yaml.Unmarshal(b, &sm.Sessions)
}

// New creates a new session with a random 16 byte hex string as its ID,
// and sets its expiration time to the current time plus the session
// manager's expiration duration. The new session is stored in the session
// manager's map of active sessions and returned.
func (s *sessionManager) NewSession(ip string, sessId string) (*Session, error) {
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
		manager: s,
		ID:      sessId,
		Shared:  sharedSession,
		Provisioning: Provisioning{
			Mutex: sync.Mutex{},
			Config: ProvisioningConfig{
				Enabled:  false,
				Strategy: JITProvisioning,
				JIT:      &JITConfig{},
				SCIM:     &scimConfig{},
			},
			Users:  map[string]User{},
			Groups: map[string]Group{},
		},
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
		if se.SAMLConfig.IdpUrl == "" && se.OIDCConfig.MetadataUrl == "" && se.Provisioning.SCIM == nil {
			delete(s.Sessions, k)
		}
	}
	b, err := yaml.Marshal(s.Sessions)
	if err != nil {
		return err
	}
	if s.Config.S3 != nil {
		_, err := s.Config.S3.PutObject(context.Background(), s.Config.S3Bucket, filepath.Base(s.Config.Filepath), bytes.NewReader(b), int64(len(b)), minio.PutObjectOptions{
			ContentType: "application/yaml",
		})
		if err != nil {
			return err
		}
		return nil
	}
	return os.WriteFile(filepath.Clean(s.Config.Filepath), b, 0600)
}

// Get returns the session with the given key. If the key is longer than 8 bytes,
// it is truncated to 8 bytes. If the session is not found, it logs a warning and
// returns nil.
func (s *sessionManager) Get(key string) *Session {
	if len(key) > 8 {
		key = key[:8]
	}
	se, ok := s.Sessions[key]
	if !ok {
		s.Config.logger.Warn().Str("id", key).Msg("session not found")
		return nil
	}
	// Fill in claims mappings if not set
	if se.Provisioning.Config.JIT == nil {
		se.Provisioning.Config.JIT = &JITConfig{
			SAMLMappings: defaultClaimMappings,
			OIDCMappings: defaultClaimMappings,
		}
	}
	if se.Provisioning.Config.SCIM == nil {
		se.Provisioning.Config.SCIM = &scimConfig{}
	} else {
		if se.Provisioning.SCIM == nil && se.Provisioning.Config.SCIM.Url != "" {
			srv, _ := scim2.GetServer(se.Provisioning.Config.SCIM.Url)
			se.Provisioning.SCIM = srv
		}
	}
	if se.Provisioning.Users == nil {
		se.Provisioning.Users = map[string]User{}
	}
	if se.Provisioning.Groups == nil {
		se.Provisioning.Groups = map[string]Group{}
	}
	se.manager = s
	return se
}

// getAnonymousPathId returns the session ID from an anonymous path, if applicable.
// An anonymous path is a path that contains a session ID but no authentication
// information. Examples include "/api/saml/<id>/metadata" or "/scim/<id>".
// If the path is not an anonymous path, an empty string is returned.
func getAnonymousPathId(path string) string {
	if (strings.HasPrefix(path, "/api/saml") || strings.HasPrefix(path, "/api/oidc")) && strings.HasSuffix(path, "/metadata") {
		p := strings.Split(path, "/")
		return p[3]
	}
	if strings.HasPrefix(path, "/scim/") {
		p := strings.Split(path, "/")
		return p[2]
	}
	return ""
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
		anonymousId := getAnonymousPathId(r.URL.Path)
		if anonymousId != "" {
			se := s.Get(anonymousId)
			if se != nil && se.Valid() {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), SessionKey, se)))
				return
			} else {
				s.Config.logger.Warn().Str("id", anonymousId).Str("path", r.URL.Path).Msg("anonymousPath: session not found")
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
				se, err = s.NewSession(r.RemoteAddr, strings.Split(r.URL.Path, "/")[2])
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
		se, err := s.NewSession(ip, "")
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
