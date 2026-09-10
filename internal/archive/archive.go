// Package archive converts PKCS #12 archives to and from PEM certificates and private keys.
package archive

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// Archive is the certificate chain and private key carried by a PKCS #12 archive.
type Archive struct {
	// Certificate is the PEM-encoded certificate chain, leaf certificate first.
	Certificate string

	// PrivateKey is the PEM-encoded PKCS #8 private key.
	PrivateKey string

	certificates []*x509.Certificate
	privateKey   any
}

// Decode reads the certificate chain and private key out of a PKCS #12 archive.
func Decode(data []byte, password string) (*Archive, error) {
	key, cert, cas, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS12 archive: %w", err)
	}

	return newArchive(append([]*x509.Certificate{cert}, cas...), key)
}

// Parse reads a PEM certificate chain and PKCS #8 private key.
func Parse(certificate, privateKey string) (*Archive, error) {
	var certificates []*x509.Certificate

	for _, block := range findBlocksByType([]byte(certificate), "CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certificates = append(certificates, cert)
	}

	if len(certificates) == 0 {
		return nil, errors.New("failed to parse certificate: no CERTIFICATE PEM block found")
	}

	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("failed to parse private key: no PEM block found")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return newArchive(certificates, key)
}

func newArchive(certificates []*x509.Certificate, privateKey any) (*Archive, error) {
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return &Archive{
		Certificate: string(encodeCertificates(certificates...)),
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: key,
		})),

		certificates: certificates,
		privateKey:   privateKey,
	}, nil
}

// Encode writes the archive in PKCS #12 form.
func (a *Archive) Encode(password string) ([]byte, error) {
	data, err := pkcs12.Encode(rand.Reader, a.privateKey, a.certificates[0], a.certificates[1:], password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS12 archive: %w", err)
	}

	return data, nil
}

// Serial returns the leaf certificate's serial number in decimal.
func (a *Archive) Serial() string {
	return a.certificates[0].SerialNumber.String()
}

func findBlocksByType(data []byte, t string) []*pem.Block {
	var blocks []*pem.Block

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == t {
			blocks = append(blocks, block)
		}

		data = rest
	}

	return blocks
}

func encodeCertificates(certs ...*x509.Certificate) []byte {
	var b bytes.Buffer

	for _, cert := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
	}

	return b.Bytes()
}
