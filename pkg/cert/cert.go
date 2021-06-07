package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"
)

type Certificate struct {
	Name       string            `json:"name"`
	Cert       *x509.Certificate `json:"-"`
	PrivteKey  *rsa.PrivateKey   `json:"-"`
	CertPEM    []byte            `json:"certificate"`
	PrivKeyPEM []byte            `json:"privateKey"`
}

func toBase64(in []byte, t string) []byte {
	block := pem.Block{
		Type:  t,
		Bytes: in,
	}
	return pem.EncodeToMemory(&block)
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
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expire),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
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
		PrivteKey:  priv,
		CertPEM:    toBase64(cert, "CERTIFICATE"),
		PrivKeyPEM: toBase64(x509.MarshalPKCS1PrivateKey(priv), "RSA PRIVATE KEY"),
	}, nil
}

func (c *Certificate) Save(rootPath string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(rootPath+"/"+c.Name+".json", b, 0644)
}

func (c *Certificate) Load(rootPath string) error {
	b, err := ioutil.ReadFile(rootPath + "/" + c.Name + ".json")
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, c); err != nil {
		return err
	}
	pb, _ := pem.Decode(c.CertPEM)
	c.Cert, err = x509.ParseCertificate(pb.Bytes)
	if err != nil {
		return err
	}
	pb, _ = pem.Decode(c.PrivKeyPEM)
	c.PrivteKey, err = x509.ParsePKCS1PrivateKey(pb.Bytes)
	return err
}
