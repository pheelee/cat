package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/crewjam/saml/samlsp"
)

type JIT struct {
	sync.Mutex `json:"-" yaml:"-"`
	Config     JITConfig `json:"config" yaml:"config"`
	Users      []User    `json:"users" yaml:"-"`
}

type JITConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type User struct {
	ID          string   `json:"id" yaml:"-"`
	DisplayName string   `json:"display_name" yaml:"-"`
	FirstName   string   `json:"first_name" yaml:"-"`
	LastName    string   `json:"last_name" yaml:"-"`
	Email       string   `json:"email" yaml:"-"`
	Roles       []string `json:"roles" yaml:"-"`
}

func (j *JIT) getUserById(id string) *User {
	for i, u := range j.Users {
		if u.ID == id {
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
	user.DisplayName = getStringClaim(claims, "display_name")
	user.FirstName = getStringClaim(claims, "first_name")
	user.LastName = getStringClaim(claims, "last_name")
	user.Email = getStringClaim(claims, "email")
	user.Roles = getStringArrayClaim(claims, "roles")
	return nil
}

func (j *JIT) AddOrUpdateUserFromSAMLAssertion(claims samlsp.JWTSessionClaims) error {
	j.Lock()
	defer j.Unlock()
	user := j.getUserById(claims.Subject)
	user.DisplayName = claims.Attributes.Get("display_name")
	user.FirstName = claims.Attributes.Get("first_name")
	user.LastName = claims.Attributes.Get("last_name")
	user.Email = claims.Attributes.Get("email")
	user.Roles = claims.Attributes["roles"]
	return nil
}
