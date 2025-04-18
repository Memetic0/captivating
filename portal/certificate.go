package portal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateSelfSignedCert generates a self-signed TLS certificate
func GenerateSelfSignedCert() (*tls.Certificate, error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Prepare certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Captive Portal"},
			CommonName:   "Captive Portal CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.1")},
		DNSNames:              []string{"localhost", "captive.portal"},
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Create tls.Certificate
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}

	return &cert, nil
}

// GetCertificateFunc returns a GetCertificate function for tls.Config
func GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var (
		cert     *tls.Certificate
		certErr  error
		certOnce bool
	)

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Generate cert only once
		if !certOnce {
			cert, certErr = GenerateSelfSignedCert()
			certOnce = true
		}
		return cert, certErr
	}
}

// generateSelfSignedCert creates a self-signed TLS certificate for HTTPS
// The certificate includes many common captive portal detection domains
// to help with smooth captive portal detection
func GenerateSelfSignedCertPEM() ([]byte, []byte, error) {
	// Generate 2048-bit RSA key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Use the current time and add 10 years for expiry
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	// Include MANY common captive portal detection domains in the certificate
	// This helps with captive portal detection systems
	captivePortalDomains := []string{
		"captiveportal.local", "*.captiveportal.local",
		"captive.apple.com", "www.apple.com", "*.apple.com",
		"connectivitycheck.gstatic.com", "*.gstatic.com",
		"www.google.com", "*.google.com",
		"clients3.google.com", "clients.google.com", "*.clients.google.com",
		"www.msftconnecttest.com", "*.msftconnecttest.com",
		"www.msftncsi.com", "*.msftncsi.com",
		"detectportal.firefox.com", "*.mozilla.com", "*.mozilla.org",
		"network-test.debian.org", "ubuntu.com", "fedoraproject.org",
		"*.apple.com.edgekey.net", "*.akamaiedge.net",
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Captivating Portal"},
			CommonName:   "captiveportal.local",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              captivePortalDomains,
		// Include all common IPs
		IPAddresses: []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate and private key in PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM, nil
}
