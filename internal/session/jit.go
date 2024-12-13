package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/crewjam/saml/samlsp"
)

var defaultClaimMappings = &claims{
	DisplayName: "display_name",
	FirstName:   "first_name",
	LastName:    "last_name",
	Email:       "email",
	Roles:       "roles",
}

type JIT struct {
	sync.Mutex `json:"-" yaml:"-"`
	Config     JITConfig `json:"config" yaml:"config"`
	Users      []User    `json:"users" yaml:"-"`
}

type JITConfig struct {
	Enabled       bool    `json:"enabled" yaml:"enabled"`
	UpdateOnLogin bool    `json:"update_on_login" yaml:"update_on_login"`
	SAMLMappings  *claims `json:"saml_mappings" yaml:"saml_mappings"`
	OIDCMappings  *claims `json:"oidc_mappings" yaml:"oidc_mappings"`
}

type claims struct {
	DisplayName string `json:"display_name" yaml:"display_name"`
	FirstName   string `json:"first_name" yaml:"first_name"`
	LastName    string `json:"last_name" yaml:"last_name"`
	Email       string `json:"email" yaml:"email"`
	Roles       string `json:"roles" yaml:"roles"`
}

type User struct {
	ID          string   `json:"id" yaml:"-"`
	Protocol    string   `json:"protocol" yaml:"-"`
	Existing    bool     `json:"-" yaml:"-"`
	DisplayName string   `json:"display_name" yaml:"-"`
	FirstName   string   `json:"first_name" yaml:"-"`
	LastName    string   `json:"last_name" yaml:"-"`
	Email       string   `json:"email" yaml:"-"`
	Roles       []string `json:"roles" yaml:"-"`
}

func (j *JIT) getUserById(id string) *User {
	for i, u := range j.Users {
		if u.ID == id {
			j.Users[i].Existing = true
			return &j.Users[i]
		}
	}
	j.Users = append(j.Users, User{ID: id})
	return &j.Users[len(j.Users)-1]
}

func getStringClaim(claims map[string]interface{}, key string) string {
	if v, ok := claims[key]; ok {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return ""
}

func getStringArrayClaim(claims map[string]interface{}, key string) []string {
	result := []string{}
	if v, ok := claims[key]; ok {
		if slice, ok := v.([]interface{}); ok {
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
		}
	}
	return result
}

func (j *JIT) AddOrUpdateUserFromJWTToken(token string) error {
	if j.Config.OIDCMappings == nil {
		j.Config.OIDCMappings = defaultClaimMappings
	}
	j.Lock()
	defer j.Unlock()
	var claims map[string]interface{}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT token")
	}
	b, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return err
	}
	user := j.getUserById(claims["sub"].(string))
	user.Protocol = "OIDC"
	if user.Existing && !j.Config.UpdateOnLogin {
		return nil
	}
	user.DisplayName = getStringClaim(claims, j.Config.OIDCMappings.DisplayName)
	user.FirstName = getStringClaim(claims, j.Config.OIDCMappings.FirstName)
	user.LastName = getStringClaim(claims, j.Config.OIDCMappings.LastName)
	user.Email = getStringClaim(claims, j.Config.OIDCMappings.Email)
	user.Roles = getStringArrayClaim(claims, j.Config.OIDCMappings.Roles)
	return nil
}

func (j *JIT) AddOrUpdateUserFromSAMLAssertion(claims samlsp.JWTSessionClaims) error {
	if j.Config.SAMLMappings == nil {
		j.Config.SAMLMappings = defaultClaimMappings
	}
	j.Lock()
	defer j.Unlock()
	user := j.getUserById(claims.Subject)
	user.Protocol = "SAML"
	if user.Existing && !j.Config.UpdateOnLogin {
		return nil
	}
	user.DisplayName = claims.Attributes.Get(j.Config.SAMLMappings.DisplayName)
	user.FirstName = claims.Attributes.Get(j.Config.SAMLMappings.FirstName)
	user.LastName = claims.Attributes.Get(j.Config.SAMLMappings.LastName)
	user.Email = claims.Attributes.Get(j.Config.SAMLMappings.Email)
	user.Roles = claims.Attributes[j.Config.SAMLMappings.Roles]
	return nil
}
