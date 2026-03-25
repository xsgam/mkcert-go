package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// Certificate file name constants
const (
	CAKeyFile  = "rootCA.key"
	CACertFile = "rootCA.pem"
)

func main() {
	// Define command line arguments
	newca := flag.Bool("newca", false, "Create CA certificate")
	ca := flag.String("ca", "", "View CA certificate information (path to rootCA.pem)")
	days := flag.Int("days", 1000, "Certificate validity period (days)")
	host := flag.String("host", "", "Hostname for certificate generation")
	cert := flag.String("cert", "", "View certificate information (path to cert file)")

	flag.Parse()

	// Handle commands
	if *newca {
		handleNewCA()
		return
	}

	if *ca != "" {
		handleCAInfo(*ca)
		return
	}

	if *cert != "" {
		handleCertInfo(*cert)
		return
	}

	if *host != "" {
		handleHostCert(*host, *days)
		return
	}

	// If no valid arguments, show help
	flag.PrintDefaults()
}

// handleNewCA creates a new CA certificate and key
func handleNewCA() {
	// Check if CA certificate already exists
	if _, err := os.Stat(CAKeyFile); err == nil {
		fmt.Printf("CA certificate already exists: %s\n", CAKeyFile)
		return
	}

	// Generate CA key (RSA 3072-bit)
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		fmt.Printf("Failed to generate CA key: %v\n", err)
		return
	}

	// Create serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fmt.Printf("Failed to generate serial number: %v\n", err)
		return
	}

	// Build CA certificate template (valid for 10 years)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "MKCert Development CA",
			Organization: []string{"MKCert"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Self-sign the CA certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		fmt.Printf("Failed to create CA certificate: %v\n", err)
		return
	}

	// Save CA private key
	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Printf("Failed to serialize CA key: %v\n", err)
		return
	}

	err = os.WriteFile(CAKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyData}), 0600)
	if err != nil {
		fmt.Printf("Failed to save CA key: %v\n", err)
		return
	}

	// Save CA certificate
	err = os.WriteFile(CACertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0644)
	if err != nil {
		fmt.Printf("Failed to save CA certificate: %v\n", err)
		return
	}

	fmt.Printf("CA certificate created successfully!\n")
	fmt.Printf("  Key:  %s\n", CAKeyFile)
	fmt.Printf("  Cert: %s\n", CACertFile)
}

// handleCAInfo displays CA certificate information
func handleCAInfo(caPath string) {
	// Read CA certificate file
	data, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Printf("Failed to read CA certificate: %v\n", err)
		return
	}

	// Parse PEM format
	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Println("Failed to parse PEM format")
		return
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse certificate: %v\n", err)
		return
	}

	// Display certificate information
	printCertInfo(cert)
}

// handleCertInfo displays certificate information
func handleCertInfo(certPath string) {
	// Read certificate file
	data, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Printf("Failed to read certificate: %v\n", err)
		return
	}

	// Parse PEM format
	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Println("Failed to parse PEM format")
		return
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse certificate: %v\n", err)
		return
	}

	// Display certificate information
	printCertInfo(cert)
}

// printCertInfo prints certificate details
func printCertInfo(cert *x509.Certificate) {
	fmt.Println("Certificate Information:")
	fmt.Printf("  Name:        %s\n", cert.Subject.CommonName)
	fmt.Printf("  Fingerprint: %s\n", getCertFingerprint(cert))
	fmt.Printf("  Created:     %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Expires:     %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
}

// handleHostCert generates a certificate for the given hostname
func handleHostCert(host string, days int) {
	if host == "" {
		fmt.Println("Please provide a hostname with -host flag")
		return
	}

	// Check if CA certificate exists
	if _, err := os.Stat(CAKeyFile); err != nil {
		fmt.Println("CA certificate does not exist, please run -newca first")
		return
	}

	// Load CA key
	caKey, err := loadCAKey()
	if err != nil {
		fmt.Printf("Failed to load CA key: %v\n", err)
		return
	}

	// Load CA certificate
	caCert, err := loadCACert()
	if err != nil {
		fmt.Printf("Failed to load CA certificate: %v\n", err)
		return
	}

	// Generate host key (RSA 3072-bit)
	hostKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		fmt.Printf("Failed to generate host key: %v\n", err)
		return
	}

	// Create serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fmt.Printf("Failed to generate serial number: %v\n", err)
		return
	}

	// Build certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add SANs (Subject Alternative Names)
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// Sign the certificate with CA
	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &hostKey.PublicKey, caKey)
	if err != nil {
		fmt.Printf("Failed to create host certificate: %v\n", err)
		return
	}

	// Generate safe filename: replace * with _wildcard
	safeHost := strings.Replace(host, "*", "_wildcard", -1)

	// Save host private key
	hostKeyData, err := x509.MarshalPKCS8PrivateKey(hostKey)
	if err != nil {
		fmt.Printf("Failed to serialize host key: %v\n", err)
		return
	}

	keyFile := safeHost + ".key"
	err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: hostKeyData}), 0600)
	if err != nil {
		fmt.Printf("Failed to save host key: %v\n", err)
		return
	}

	// Save host certificate
	certFile := safeHost + ".crt"
	err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0644)
	if err != nil {
		fmt.Printf("Failed to save certificate: %v\n", err)
		return
	}

	fmt.Printf("Certificate created successfully for %s\n", host)
	fmt.Printf("  Key:  %s\n", keyFile)
	fmt.Printf("  Cert: %s\n", certFile)
}

// loadCAKey reads and parses the CA private key from file
func loadCAKey() (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(CAKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM format")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA private key")
	}

	return rsaKey, nil
}

// loadCACert reads and parses the CA certificate from file
func loadCACert() (*x509.Certificate, error) {
	data, err := os.ReadFile(CACertFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM format")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// getCertFingerprint returns the SHA1 fingerprint of a certificate
func getCertFingerprint(cert *x509.Certificate) string {
	hash := sha1.Sum(cert.Raw)
	return hex.EncodeToString(hash[:])
}
