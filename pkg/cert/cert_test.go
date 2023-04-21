package cert

import (
	"os"
	"testing"
)

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
	if c.PrivteKey == nil {
		t.Fatal("expected private key, got nil")
	}
	if c.CertPEM == nil {
		t.Fatal("expected certificate pem, got nil")
	}
	if c.PrivKeyPEM == nil {
		t.Fatal("expected private key pem, got nil")
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

	// Update CertPEM with invalid data
	c.CertPEM = []byte("invalid")
	// Save cert with invalid data
	if err := c.Save("/tmp"); err != nil {
		t.Fatal(err)
	}
	// Test ParseCertificate error in Load function
	err = c.Load("/tmp")
	if err == nil {
		t.Fatal("expected error, got nil")
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
