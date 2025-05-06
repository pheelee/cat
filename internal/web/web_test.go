package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pheelee/Cat/internal/session"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJsonResponse(t *testing.T) {
	w := httptest.NewRecorder()
	jsonResponse(w, map[string]string{"hello": "world"})
	assert.Equal(t, w.Code, 200)
	assert.Equal(t, "{\"hello\":\"world\"}\n", w.Body.String())
	// Test invalid json data
	w = httptest.NewRecorder()
	c := make(chan int)
	jsonResponse(w, c)
	assert.Equal(t, w.Code, 500)
}

func TestJsonError(t *testing.T) {
	w := httptest.NewRecorder()
	jsonError(w, 500, errors.New("test error"))
	assert.Equal(t, w.Code, 500)
	assert.Equal(t, "{\"error\":\"test error\"}\n", w.Body.String())
}

func TestRandomString(t *testing.T) {
	assert.Equal(t, 43, len(randomString(43)))
}

func TestReferrerHost(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Referer", "https://cat.example.com/oidc/callback")
	assert.Equal(t, "https://cat.example.com", referrerHost(r))
}

func TestFrontend(t *testing.T) {
	r := GetRouter(zerolog.Nop(), time.Hour)
	assert.NotNil(t, r)
	s := httptest.NewServer(r)
	defer s.Close()
	resp, err := s.Client().Get(s.URL + "/favicon.ico")
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	resp, err = s.Client().Get(s.URL + "/oidc/callback")
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(b), "<!DOCTYPE html>")
}

func TestUserInfo(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), session.SessionKey, &session.Session{
		ID:      "testtest",
		Expires: time.Now().Add(time.Hour),
	}))
	w := httptest.NewRecorder()
	userinfo(w, req)
	assert.Equal(t, 200, w.Code)
	var u userInfo
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &u))
	assert.Equal(t, "testtest", u.ID)
}

func TestGetSamlConfig(t *testing.T) {
	sm, err := session.NewManager(zerolog.Nop(), time.Hour, "/tmp/session.yaml", "")
	require.NoError(t, err)
	s, err := sm.NewSession("1.2.3.4", "")
	require.NoError(t, err)
	s.SAMLConfig.SPEntityID = "testSP"
	require.Nil(t, err)
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Referer", "https://cat.example.com/saml")
	req = req.WithContext(context.WithValue(req.Context(), session.SessionKey, s))
	w := httptest.NewRecorder()
	getSamlConfig(w, req)
	assert.Equal(t, 200, w.Code)
	var u session.SamlParams
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &u))
	assert.Equal(t, "https://cat.example.com/api/saml/"+s.ID[:8]+"/metadata", u.SPMetadataUrl)
}

func TestPutSamlConfig(t *testing.T) {
	sm, err := session.NewManager(zerolog.Nop(), time.Hour, "/tmp/session.yaml", "")
	require.NoError(t, err)
	s, err := sm.NewSession("1.2.3.4", "")
	require.NoError(t, err)
	s.SAMLConfig.SPEntityID = "testSP"
	require.Nil(t, err)
	var body = session.SamlParams{
		SPEntityID: "testSP",
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, _ := http.NewRequest("PUT", "/", bytes.NewReader(b))
	req.Header.Set("Referer", "https://cat.example.com/saml")
	req = req.WithContext(context.WithValue(req.Context(), session.SessionKey, s))
	w := httptest.NewRecorder()
	putSamlConfig(w, req)
	assert.Equal(t, 200, w.Code)

	// Test body read: howto do that?

	// Test json decode error
	req, _ = http.NewRequest("PUT", "/", bytes.NewReader([]byte{}))
	req = req.WithContext(context.WithValue(req.Context(), session.SessionKey, s))
	w = httptest.NewRecorder()
	putSamlConfig(w, req)
	assert.Equal(t, 400, w.Code)

	// Test Idp Metadata Fetch
	metadataSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/valid" {
			_, _ = w.Write([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2024-10-14T17:25:24.463Z" entityID="https://cat.example.com/3a607a03"><SPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2024-10-14T17:25:24.462646184Z" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">MIIDQzCCAiugAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJDSDENMAsGA1UEChMESVJCRTELMAkGA1UECxMCSVQxKTAnBgNVBAMTIGNhdC10b2tlbnNpZ25lci0zYTYwN2EwMy1wcmltYXJ5MB4XDTI0MTAxMDE3MTY1M1oXDTI0MTEwOTE3MTY1M1owVDELMAkGA1UEBhMCQ0gxDTALBgNVBAoTBElSQkUxCzAJBgNVBAsTAklUMSkwJwYDVQQDEyBjYXQtdG9rZW5zaWduZXItM2E2MDdhMDMtcHJpbWFyeTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJMelO9eZHRhXtFAquEm23GUthosxVcKF8moXicoELcgz+q32aoFMcM5uDZSPmsL8IBm3VpCV+UrKAFNeNb9hQv1OeVegIcmW99OKalwTAgQcq8nw2XFcjyVKho3Loa0YnzQznO4h6iFH4Sdz97T/4TShV72crYf/c7KNrnkvPtgP8UGv3nkUA6sSEC9eGMd8hYw9S8i5tSyNu7jU4uFg8Setbgw7vE//og8I0xvNT4h1o+NRcBI7tyKhPiKkqDIHFaa1QCzRxDq+U41W4OseVrqPJLU52ADYdu0A+ddPFWsnoj7tVavyuBbrc0rOEnlFlMz7HoAkb12c31kfWfpHkCAwEAAaMgMB4wDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAK+NXEN/mGyBwBWqyxRwEh2GnhD61hLUSN/mbG334Q6oh301shyWG6zYLYXiV7oCx9RBqe0bE3oaaAF7VSi2YzcDV4TOOJ+5We4+H2oaZdXNsIgAG/dywe/Cp4QRXlMswx6+ZnhRgcITXWMtgNwriYscPr7qKcMLLgJEd7yyMenO0D9/qWHUtFCCJgE52hN0rCG43qD2hp1up2tKcMhVoo3+qGqu4lkZlvm+Yo0gSKkQQYF/CgpKlaz1X7Oz8vs+QPEG3wL5o60rKR3z9Uva+YxcK6go+EzZylilTMZRBCcSglaQPKJRVa0K5igx5+RVms/xX0iS84PiFIUpWxUtTlI=</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://cat.example.com/saml/slo" ResponseLocation="https://cat.example.com/saml/slo"></SingleLogoutService><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://cat.example.com/api/saml/3a607a03/acs" index="1"></AssertionConsumerService><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://cat.example.com/api/saml/3a607a03/acs" index="2"></AssertionConsumerService></SPSSODescriptor></EntityDescriptor>`))
			return
		}
		if r.URL.Path == "/invalid" {
			_, _ = w.Write([]byte("invalid"))
			return
		}
	}))
	body.IdpUrl = metadataSrv.URL + "/valid"
	b, err = json.Marshal(body)
	require.NoError(t, err)
	req, _ = http.NewRequest("PUT", "/valid", bytes.NewReader(b))
	req.Header.Set("Referer", "https://cat.example.com/saml")
	req = req.WithContext(context.WithValue(req.Context(), session.SessionKey, s))
	w = httptest.NewRecorder()
	putSamlConfig(w, req)
	assert.Equal(t, 200, w.Code)

	// Test invalid Metadata
	body.IdpUrl = metadataSrv.URL + "/invalid"
	b, err = json.Marshal(body)
	require.NoError(t, err)
	req, _ = http.NewRequest("PUT", "/invalid", bytes.NewReader(b))
	req.Header.Set("Referer", "https://cat.example.com/saml")
	req = req.WithContext(context.WithValue(req.Context(), session.SessionKey, s))
	w = httptest.NewRecorder()
	putSamlConfig(w, req)
	assert.Equal(t, 400, w.Code)

	// Test Idp Metadata URL unreachable
	body.IdpUrl = "https://1.2.3.4/metdata"
	b, err = json.Marshal(body)
	require.NoError(t, err)
	req, _ = http.NewRequest("PUT", "/", bytes.NewReader(b))
	req.Header.Set("Referer", "https://cat.example.com/saml")
	req = req.WithContext(context.WithValue(req.Context(), session.SessionKey, s))
	w = httptest.NewRecorder()
	putSamlConfig(w, req)
	assert.Equal(t, 400, w.Code)
}
