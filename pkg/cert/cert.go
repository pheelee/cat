package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Certificate struct {
	Name       string            `json:"name"`
	Cert       *x509.Certificate `json:"-"`
	PrivateKey *rsa.PrivateKey   `json:"-"`
	CertPEM    []byte            `json:"certificate"`
	PrivKeyPEM []byte            `json:"privateKey"`
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

func (c *Certificate) MarshalJSON() ([]byte, error) {
	type t Certificate
	crt := t{
		Name:       c.Name,
		Cert:       c.Cert,
		PrivateKey: c.PrivateKey,
	}
	crt.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Cert.Raw})
	crt.PrivKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(crt.PrivateKey)})
	return json.Marshal(&crt)
}

func (c *Certificate) UnmarshalJSON(b []byte) error {
	type t Certificate
	var (
		crt t
		err error
	)
	if err := json.Unmarshal(b, &crt); err != nil {
		return err
	}
	p, _ := pem.Decode(crt.CertPEM)
	if p == nil {
		return errors.New("failed to parse certificate PEM")
	}
	c.Cert, err = x509.ParseCertificate(p.Bytes)
	if err != nil {
		return err
	}
	c.CertPEM = crt.CertPEM
	p, _ = pem.Decode(crt.PrivKeyPEM)
	if p == nil {
		return errors.New("failed to parse private key PEM")
	}
	c.PrivateKey, err = x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return err
	}
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
