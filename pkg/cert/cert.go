package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Certificate struct {
	Name       string            `json:"name" yaml:"name"`
	Cert       *x509.Certificate `json:"-" yaml:"-"`
	PrivateKey *rsa.PrivateKey   `json:"-" yaml:"-"`
	CertPEM    []byte            `json:"certificate" yaml:"certificate"`
	PrivKeyPEM []byte            `json:"-" yaml:"privateKey"`
}

func Generate(name string, org string, country string, ou string, expires string) (*Certificate, error) {
	expire, err := time.ParseDuration(expires)
	if err != nil {
		return nil, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{org},
			Country:            []string{country},
			OrganizationalUnit: []string{ou},
			CommonName:         name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expire),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	crt, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	return &Certificate{
		Name:       name,
		Cert:       crt,
		PrivateKey: priv,
		CertPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw}),
	}, nil
}

func (c *Certificate) MarshalYAML() (interface{}, error) {
	return map[string]interface{}{
		"name":        c.Name,
		"certificate": base64.RawStdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})),
		"privateKey":  base64.RawStdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.PrivateKey)})),
	}, nil
}

func (c *Certificate) UnmarshalYAML(value *yaml.Node) error {
	var err error
	var temp struct {
		Name       string `yaml:"name"`
		CertPEM    string `yaml:"certificate"`
		PrivKeyPEM string `yaml:"privateKey"`
	}

	if err := value.Decode(&temp); err != nil {
		return err
	}

	c.Name = temp.Name
	if c.CertPEM, err = base64.RawStdEncoding.DecodeString(temp.CertPEM); err != nil {
		return err
	}
	if c.PrivKeyPEM, err = base64.RawStdEncoding.DecodeString(temp.PrivKeyPEM); err != nil {
		return err
	}
	p, _ := pem.Decode(c.CertPEM)
	if p == nil {
		return errors.New("failed to parse certificate PEM")
	}
	c.Cert, err = x509.ParseCertificate(p.Bytes)
	if err != nil {
		return err
	}
	p, _ = pem.Decode(c.PrivKeyPEM)
	if p == nil {
		return errors.New("failed to parse private key PEM")
	}
	c.PrivateKey, err = x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return err
	}
	c.PrivKeyPEM = []byte{}
	return nil
}

func (c *Certificate) Save(rootPath string) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(rootPath+"/"+c.Name+".json", b, 0600)
}

func (c *Certificate) Load(rootPath string) error {
	b, err := os.ReadFile(filepath.Clean(rootPath) + "/" + c.Name + ".json")
	if err != nil {
		return err
	}
	return json.Unmarshal(b, c)
}
