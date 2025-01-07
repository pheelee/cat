package session

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/crewjam/saml/samlsp"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestGetUserById(t *testing.T) {
	j := Provisioning{
		Users: map[string]User{
			"test": {ID: "test"}},
	}
	assert.NotNil(t, j.getUserById("test"))
	assert.NotNil(t, j.getUserById("testtest"))
}

func TestGetStringClaim(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]interface{}
		key      string
		expected string
	}{
		{
			name:     "Key exists with string value",
			claims:   map[string]interface{}{"username": "johndoe"},
			key:      "username",
			expected: "johndoe",
		},
		{
			name:     "Key exists with non-string value",
			claims:   map[string]interface{}{"age": 30},
			key:      "age",
			expected: "",
		},
		{
			name:     "Key does not exist",
			claims:   map[string]interface{}{"role": "admin"},
			key:      "username",
			expected: "",
		},
		{
			name:     "Empty claims map",
			claims:   map[string]interface{}{},
			key:      "username",
			expected: "",
		},
		{
			name:     "Nil claims map",
			claims:   nil,
			key:      "username",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringClaim(tt.claims, tt.key)
			assert.Equal(t, tt.expected, result, "Result should match expected value")
		})
	}
}

func TestGetStringArrayClaim(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]interface{}
		key      string
		expected []string
	}{
		{
			name:     "Key exists with valid string array",
			claims:   map[string]interface{}{"roles": []interface{}{"admin", "user"}},
			key:      "roles",
			expected: []string{"admin", "user"},
		},
		{
			name:     "Key exists with empty array",
			claims:   map[string]interface{}{"roles": []interface{}{}},
			key:      "roles",
			expected: []string{},
		},
		{
			name:     "Key does not exist",
			claims:   map[string]interface{}{"permissions": []interface{}{"read", "write"}},
			key:      "roles",
			expected: []string{},
		},
		{
			name:     "Key exists but with non-array value",
			claims:   map[string]interface{}{"roles": "not-an-array"},
			key:      "roles",
			expected: []string{},
		},
		{
			name:     "Nil claims map",
			claims:   nil,
			key:      "roles",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringArrayClaim(tt.claims, tt.key)
			assert.Equal(t, tt.expected, result, "Result should match expected value")
		})
	}
}

func TestAddOrUpdateUserFromJWTToken(t *testing.T) {
	j := &Provisioning{
		Users: map[string]User{
			"12345": {ID: "12345"},
		},
		Config: ProvisioningConfig{
			JIT: &JITConfig{
				UpdateOnLogin: true,
			},
		},
	}

	// Mock JWT token with encoded claims
	claims := map[string]interface{}{
		"sub":          "12345",
		"display_name": "John Doe",
		"first_name":   "John",
		"last_name":    "Doe",
		"email":        "john.doe@example.com",
		"roles":        []interface{}{"admin", "user"},
	}
	claimsJson, _ := json.Marshal(claims)
	encodedClaims := base64.RawStdEncoding.EncodeToString(claimsJson)
	mockToken := "header." + encodedClaims + ".signature"

	err := j.AddOrUpdateUserFromJWTToken(mockToken)
	assert.NoError(t, err)

	user := j.Users["12345"]
	assert.NotNil(t, user)
	assert.Equal(t, "John Doe", user.DisplayName)
	assert.Equal(t, "John", user.FirstName)
	assert.Equal(t, "Doe", user.LastName)
	assert.Equal(t, "john.doe@example.com", user.Email)
	assert.Equal(t, []string{"admin", "user"}, user.Roles)
	// Test with update disabled
	j.Config.JIT.UpdateOnLogin = false
	claims["first_name"] = "Jane"
	claimsJson, _ = json.Marshal(claims)
	encodedClaims = base64.RawStdEncoding.EncodeToString(claimsJson)
	mockToken = "header." + encodedClaims + ".signature"
	assert.Nil(t, j.AddOrUpdateUserFromJWTToken(mockToken))
	assert.Equal(t, "John", j.Users["12345"].FirstName)
	// Test invalid token format
	err = j.AddOrUpdateUserFromJWTToken("invalid-token")
	assert.Error(t, err)
	// Test invalid base64 encoding for part 2 of the token
	invalidToken := "header." + "invalid-claims" + ".signature"
	err = j.AddOrUpdateUserFromJWTToken(invalidToken)
	assert.Error(t, err)
	// Test json unmarshall error of part 2 after base64 decode
	invalidToken = "header." + base64.RawStdEncoding.EncodeToString([]byte("invalid-claims")) + ".signature"
	err = j.AddOrUpdateUserFromJWTToken(invalidToken)
	assert.Error(t, err)
}

func TestAddOrUpdateUserFromSAMLAssertion(t *testing.T) {
	j := &Provisioning{
		Users: map[string]User{
			"12345": {ID: "12345"},
		},
		Config: ProvisioningConfig{
			JIT: &JITConfig{
				UpdateOnLogin: true,
			},
		},
	}

	claims := samlsp.JWTSessionClaims{
		StandardClaims: jwt.StandardClaims{ //nolint
			Subject: "12345",
		},
		Attributes: samlsp.Attributes{
			"display_name": {"John Doe"},
			"first_name":   {"John"},
			"last_name":    {"Doe"},
			"email":        {"john.doe@example.com"},
			"roles":        {"admin", "user"},
		},
	}

	err := j.AddOrUpdateUserFromSAMLAssertion(claims)
	assert.NoError(t, err)

	user := j.Users["12345"]
	assert.NotNil(t, user)
	assert.Equal(t, "John Doe", user.DisplayName)
	assert.Equal(t, "John", user.FirstName)
	assert.Equal(t, "Doe", user.LastName)
	assert.Equal(t, "john.doe@example.com", user.Email)
	assert.Equal(t, []string{"admin", "user"}, user.Roles)
	// Test with update disabled
	j.Config.JIT.UpdateOnLogin = false
	claims.Attributes["first_name"][0] = "Jane"
	err = j.AddOrUpdateUserFromSAMLAssertion(claims)
	assert.Nil(t, err)
	assert.Equal(t, "John", j.Users["12345"].FirstName)
	// Test invalid claims
	invalidClaims := samlsp.JWTSessionClaims{
		StandardClaims: jwt.StandardClaims{ //nolint
			Subject: "12345",
		},
		Attributes: samlsp.Attributes{
			"first_name": {"John"},
		},
	}
	err = j.AddOrUpdateUserFromSAMLAssertion(invalidClaims)
	assert.Nil(t, err)
	assert.Equal(t, "John", j.Users["12345"].FirstName)
}
