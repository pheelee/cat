package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/crewjam/saml/samlsp"
	"github.com/pheelee/Cat/internal/scim2"
)

type ProvisioningStrategy int

const (
	JITProvisioning  ProvisioningStrategy = iota //0
	SCIMProvisioning                             //1
)

type Provisioning struct {
	sync.Mutex `json:"-" yaml:"-"`
	Users      map[string]User     `json:"users" yaml:"users"`
	Groups     map[string]Group    `json:"groups" yaml:"groups"`
	Config     ProvisioningConfig  `json:"config" yaml:"config"`
	SCIM       *scim2.SCIMInstance `json:"-" yaml:"-"`
}

var defaultClaimMappings = &claims{
	DisplayName: "display_name",
	FirstName:   "first_name",
	LastName:    "last_name",
	Email:       "email",
	Roles:       "roles",
}

type ProvisioningConfig struct {
	Enabled  bool                 `json:"enabled" yaml:"enabled"`
	Strategy ProvisioningStrategy `json:"strategy" yaml:"strategy"`
	JIT      *JITConfig           `json:"jit" yaml:"jit"`
	SCIM     *scimConfig          `json:"scim" yaml:"scim"`
}

type scimConfig struct {
	Url   string `json:"url" yaml:"url"`
	Token string `json:"token" yaml:"token"`
}

type JITConfig struct {
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
	ID          string   `json:"id" yaml:"id"`
	Protocol    string   `json:"protocol" yaml:"protocol"`
	Existing    bool     `json:"-" yaml:"-"`
	DisplayName string   `json:"display_name" yaml:"display_name"`
	FirstName   string   `json:"first_name" yaml:"first_name"`
	LastName    string   `json:"last_name" yaml:"last_name"`
	Email       string   `json:"email" yaml:"email"`
	Roles       []string `json:"roles" yaml:"roles"`
}

type Group struct {
	ID          string `json:"id" yaml:"id"`
	DisplayName string `json:"display_name" yaml:"display_name"`
}

func (p *Provisioning) getUserById(id string) *User {
	u, ok := p.Users[id]
	if ok {
		u.Existing = true
		return &u
	}
	user := User{ID: id}
	p.Users[id] = user
	return &user
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

func (p *Provisioning) AddOrUpdateUserFromJWTToken(token string) error {
	if p.Config.JIT.OIDCMappings == nil {
		p.Config.JIT.OIDCMappings = defaultClaimMappings
	}
	p.Lock()
	defer p.Unlock()
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
	user := p.getUserById(claims["sub"].(string))
	user.Protocol = "OIDC"
	if user.Existing && !p.Config.JIT.UpdateOnLogin {
		return nil
	}
	user.DisplayName = getStringClaim(claims, p.Config.JIT.OIDCMappings.DisplayName)
	user.FirstName = getStringClaim(claims, p.Config.JIT.OIDCMappings.FirstName)
	user.LastName = getStringClaim(claims, p.Config.JIT.OIDCMappings.LastName)
	user.Email = getStringClaim(claims, p.Config.JIT.OIDCMappings.Email)
	user.Roles = getStringArrayClaim(claims, p.Config.JIT.OIDCMappings.Roles)
	p.Users[user.ID] = *user
	return nil
}

func (p *Provisioning) AddOrUpdateUserFromSAMLAssertion(claims samlsp.JWTSessionClaims) error {
	if p.Config.JIT.SAMLMappings == nil {
		p.Config.JIT.SAMLMappings = defaultClaimMappings
	}
	p.Lock()
	defer p.Unlock()
	user := p.getUserById(claims.Subject)
	user.Protocol = "SAML"
	if user.Existing && !p.Config.JIT.UpdateOnLogin {
		return nil
	}
	user.DisplayName = claims.Attributes.Get(p.Config.JIT.SAMLMappings.DisplayName)
	user.FirstName = claims.Attributes.Get(p.Config.JIT.SAMLMappings.FirstName)
	user.LastName = claims.Attributes.Get(p.Config.JIT.SAMLMappings.LastName)
	user.Email = claims.Attributes.Get(p.Config.JIT.SAMLMappings.Email)
	user.Roles = claims.Attributes[p.Config.JIT.SAMLMappings.Roles]
	p.Users[user.ID] = *user
	return nil
}
