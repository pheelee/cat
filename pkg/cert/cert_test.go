package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var certPEM = `
-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBAMQ0wCwYDVQQGEwRUZXN0
MQ0wCwYDVQQKEwRUZXN0MQ0wCwYDVQQLEwRUZXN0MREwDwYDVQQDEwhVbml0VGVz
dDAeFw05OTAxMDExMjAwMDBaFw05OTAxMDExMzAwMDBaMEAxDTALBgNVBAYTBFRl
c3QxDTALBgNVBAoTBFRlc3QxDTALBgNVBAsTBFRlc3QxETAPBgNVBAMTCFVuaXRU
ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0txEF40idKt6juJX
btKCYwMCdnz96DFK88WftbYezvFgGCpq7D1IL2TQlzvoCHRN6gelujkPNCeq/L1b
ywhk73h8JawdRtUrHveHJXtZBtx6HKYms/EJ6RGtQ0UzYTano6UUkmybWf+4wSn5
8udizL/vBUMfKHYVymHcIuLzsniKTv+WAIMz3zNOb6oLvBJtVbWejnkH2EHKzJPO
pW7jkDk+jP0gwsee/TsNqEpxPPK0J8r2WP9TEL0VIKzKOt0kAeqZRZvXCiqSKrWB
v080+U2UBtJCWQZV2bZHoY2oTTK+KNJzD9e41uZDQpO0Rqo4UZRWNckcsyoJKWEY
PfbW7QIDAQABoyAwHjAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADANBgkq
hkiG9w0BAQsFAAOCAQEAgEVdPx9AqEXvB1/oMNjyp/UBeRt3+X+rhQaMQ3bEMDdI
oX+M9+ircDvcLs2biXWmWtkiYKWqCEuXJ4ZOCPtn2EG2OIp1JEdh0A/1F5GQajxi
CYz3CsnuRD/YImOm1p+kJhHBgDneImXPDGzROj1DJNNRU8UXWjYLAmiZ5r9AE+9s
2ljqRzseyHtPk6PcdSM7743K0PHU7nI00/Xaqi/HIPp7LAOAAJ0q6kxQ3UnZqReQ
VeMe1KzEHmPrWcTiCIZnb+1HmOIMTKqVRIupdrNoVUvNaZZplm3hNnNpgVXVdfAG
qzrLeho3a0BR3LBN52MgtZZG1A0xSReFTYnrmL3kGA==
-----END CERTIFICATE-----
`

var privKeyPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0txEF40idKt6juJXbtKCYwMCdnz96DFK88WftbYezvFgGCpq
7D1IL2TQlzvoCHRN6gelujkPNCeq/L1bywhk73h8JawdRtUrHveHJXtZBtx6HKYm
s/EJ6RGtQ0UzYTano6UUkmybWf+4wSn58udizL/vBUMfKHYVymHcIuLzsniKTv+W
AIMz3zNOb6oLvBJtVbWejnkH2EHKzJPOpW7jkDk+jP0gwsee/TsNqEpxPPK0J8r2
WP9TEL0VIKzKOt0kAeqZRZvXCiqSKrWBv080+U2UBtJCWQZV2bZHoY2oTTK+KNJz
D9e41uZDQpO0Rqo4UZRWNckcsyoJKWEYPfbW7QIDAQABAoIBAC2Qr54vP2zayWcq
/h3Sm55tvhCAvhV44WuAHx0TN+EcQ9m1ANn//CNRs8mahm+dQmD6OhPd1K0+jTKE
cNuU+srMzHcPlFwEIIdWkfvFhd13s2ORe/eSdMPKsBhDUfEF8H/qYmGp2oA+RFxp
h7u3yJ/aMfp/ILKLofXT49AeHu9HvFJCOdMw+hGVzUqH0NQetj2VMSZ9jSgPed7+
T4pfsjGFjsrXqJMUOLSmB8wRI050W4VkpHp9nq+Zn2T3EFX7ezwvELh3yWXsVyih
1bkXWPqTz2ojqWdjqIQRbPTSudFI8XXwKOcnCiPb3uosjRrYqKw1zaJX9saJswk8
45Xd+nkCgYEA1sbd4AdNluDgSxtpIH023sVguyqCa1+pdkRntN1A0cooUFPtIe0i
nJVbAqiv34NztcWEVBUQguy/2nqa6s8ciU/aHNqF/W4eRH1c2QuUt+pc91iBDcPE
IYBo3PVbFjAju+C/LT1oDRWOVHVWIQk3sIqsxR7y0r/vrd1EBNeBED8CgYEA+1T3
FbemPlWi5T5lqXv29FRT5huSeTqUwJXDNgFQzWLd1y+nj0n4huQeuW9xzMUbdvV9
AqpHzPkkZqwr4SMpB040Qt77pDd5kxwQtTr+dH3OoNblzYcagpbMw/ddlNMl4V3G
JJwZYuP6WspJHvuLaZLMorFvVz7QwtvlUBZszdMCgYAmvwOh+c9Oi80K36wMd2ph
r/vuaBHVKxHYSyjmYQ/jiPPS4gEioLQgyXT8us/Xo9BJF5Py00YCSJGn6XxvJeQB
BY3UrLuFZ8tAEdmhMkynDTmuSaImiI2meZLxYbYH/7FCoJ38nFpcGepuZCiglxgb
2jim6xllWcj0dbliojofYwKBgDpu7adx9EfH10CfOjmmZas2s+7q+CoRUaZY63Lx
6VxnIRa3sKhi1VJfVTldzMKEDTeiKbdl6Z2hSzJH00fbyd019Habqzvp3e0y+Dt6
hNCGs3S3oeQgBizYbLEfIPXKBaOZDslSNaDFSl6zaz610xrvk3477JwHMbgsMetl
21QbAoGBAJnD0gD7yA3YaGOutaoCp4uFAGw9K8Of46iKA0QChty0Ep5UYEqVYzMI
BcEeg+9VM43gx0aFS1qU8HP+mlUL8gRGxHmaUe/l27a+rcN84Nkr6B+98AKm8h/d
QB4HtPhud8xCVFebIBt/NlhNdBJrBPJXZodkZsYP5XCvr/FFQyFb
-----END RSA PRIVATE KEY-----
`

// TestGenerate tests the Generate function.
func TestGenerate(t *testing.T) {
	c, err := Generate("test", "test", "test", "test", "1h")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "test" {
		t.Fatalf("expected %s, got %s", "test", c.Name)
	}
	if c.Cert == nil {
		t.Fatal("expected certificate, got nil")
	}
	if c.PrivateKey == nil {
		t.Fatal("expected private key, got nil")
	}
	if c.CertPEM == nil {
		t.Fatal("expected certificate PEM, got nil")
	}
	if c.PrivKeyPEM != nil {
		t.Fatal("expected nil")
	}

	// Test invalid expires string
	_, err = Generate("test", "test", "test", "test", "invalid")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestSave tests the Save function.
func TestSave(t *testing.T) {
	c, err := Generate("test", "test", "test", "test", "1h")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Save("/tmp"); err != nil {
		t.Fatal(err)
	}
}

// TestLoad tests the Load function.
func TestLoad(t *testing.T) {
	c, err := Generate("test", "test", "test", "test", "1h")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Save("/tmp"); err != nil {
		t.Fatal(err)
	}
	err = c.Load("/tmp")
	if err != nil {
		t.Fatal(err)
	}

	// Test invalid file
	err = c.Load("/tmp/invalid")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// write invalid json to file
	if err := os.WriteFile("/tmp/cert.json", []byte("invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	c = &Certificate{Name: "cert"}
	// Test invalid json
	err = c.Load("/tmp")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestMarshalYaml(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tt, _ := time.Parse(time.RFC822, "01 Jan 99 12:00 UTC")
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"Test"},
			Country:            []string{"Test"},
			OrganizationalUnit: []string{"Test"},
			CommonName:         "UnitTest",
		},
		NotBefore:             tt,
		NotAfter:              tt.Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	c := &Certificate{
		Name:       "test",
		Cert:       crt,
		PrivateKey: priv,
	}
	x, err := c.MarshalYAML()
	if err != nil {
		t.Fatal(err)
	}

	if x.(map[string]interface{})["name"] != "test" {
		t.Errorf("Expected name to be 'test', got %s", x.(map[string]interface{})["name"])
	}
}

func TestUnmarshalYaml(t *testing.T) {
	// Mock YAML data with base64-encoded certificate and private key
	mockYAML := `
name: TestCert
certificate: ` + base64.RawStdEncoding.EncodeToString([]byte(certPEM)) + `
privateKey: ` + base64.RawStdEncoding.EncodeToString([]byte(privKeyPEM)) + `
`

	// Create an empty Certificate object
	var cert Certificate

	// Unmarshal YAML
	err := yaml.Unmarshal([]byte(mockYAML), &cert)
	if err != nil {
		t.Fatalf("UnmarshalYAML failed: %v", err)
	}

	// Check if the certificate and private key were decoded correctly
	if cert.Name != "TestCert" {
		t.Errorf("Expected Name to be 'TestCert', got %s", cert.Name)
	}

	// Check if CertPEM and PrivKeyPEM are decoded correctly
	if len(cert.CertPEM) == 0 {
		t.Error("CertPEM was not decoded correctly")
	}

	if cert.PrivateKey == nil {
		t.Error("PrivateKey was not decoded correctly")
	}

	// Test incomplete data
	mockInvalidCert := `
name: TestCert
certificate: ` + base64.RawStdEncoding.EncodeToString([]byte(certPEM[:10])) + `
privateKey: ` + base64.RawStdEncoding.EncodeToString([]byte(privKeyPEM)) + `
`
	if err := yaml.Unmarshal([]byte(mockInvalidCert), &cert); err == nil {
		t.Error("Expected error, got nil")
	}
	mockInvalidPrivKey := `
name: TestCert
certificate: ` + base64.RawStdEncoding.EncodeToString([]byte(certPEM)) + `
privateKey: ` + base64.RawStdEncoding.EncodeToString([]byte(privKeyPEM[:10])) + `
`
	if err := yaml.Unmarshal([]byte(mockInvalidPrivKey), &cert); err == nil {
		t.Error("Expected error, got nil")
	}

	mockInvalidCertBase64 := `
name: TestCert
certificate: invalid!!base64
privateKey: ` + base64.RawStdEncoding.EncodeToString([]byte(privKeyPEM)) + `
`
	if err := yaml.Unmarshal([]byte(mockInvalidCertBase64), &cert); err == nil {
		t.Error("Expected error, got nil")
	}

	mockInvalidPrivKeyBase64 := `
name: TestCert
certificate: ` + base64.RawStdEncoding.EncodeToString([]byte(certPEM)) + `
privateKey: invalid!!base64
`
	if err := yaml.Unmarshal([]byte(mockInvalidPrivKeyBase64), &cert); err == nil {
		t.Error("Expected error, got nil")
	}

}
