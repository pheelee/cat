package session

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func (s *Session) GenerateJWT() (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  s.ID,
		"iat": time.Now().Unix(),
		"exp": s.Expires.Unix(),
	}).SignedString([]byte(s.manager.Config.Secret))
}

func (s *Session) ValidateJWT(token string) bool {
	token = strings.TrimPrefix(token, "Bearer ")
	t, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(s.manager.Config.Secret), nil
	})

	return err == nil &&
		t.Valid &&
		t.Claims.(jwt.MapClaims)["id"].(string) == s.ID &&
		time.Now().Unix() < int64(t.Claims.(jwt.MapClaims)["exp"].(float64))
}
