package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"software.sslmate.com/src/go-pkcs12"
)

func dataSourceArchive() *schema.Resource {
	return &schema.Resource{
		Description: "Read the content of a PKCS12 archive or create a new archive by specifying its content",

		ReadContext: dataSourceArchiveRead,

		Schema: map[string]*schema.Schema{
			"archive": {
				Description:  "The PKCS12 archive, base64 encoded",
				Type:         schema.TypeString,
				Optional:     true,
				ExactlyOneOf: []string{"certificate"},
				Computed:     true,
			},
			"password": {
				Description: "The password for the PKCS12 archive",
				Type:        schema.TypeString,
				Required:    true,
			},
			"certificate": {
				Description: "The certificate in PEM format. The leaf certificate should be followed by any CA certificates.",
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
			},
			"private_key": {
				Description:  "The private key in PEM format",
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"certificate"},
				Computed:     true,
				Sensitive:    true,
			},
		},
	}
}

func dataSourceArchiveRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	password := d.Get("password").(string)

	if v, ok := d.GetOk("archive"); ok {
		archive, err := base64.StdEncoding.DecodeString(v.(string))
		if err != nil {
			return diag.Errorf("failed to decode archive as base64: %v", err)
		}

		key, cert, cas, err := pkcs12.DecodeChain(archive, password)
		if err != nil {
			return diag.Errorf("failed to decode PKCS12 archive: %v", err)
		}

		certs := append([]*x509.Certificate{cert}, cas...)

		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return diag.Errorf("failed to marshal private key: %v", err)
		}

		d.Set("private_key", string(pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})))

		d.Set("certificate", string(encodeCertificates(certs...)))

		d.SetId(cert.SerialNumber.String())
		return nil
	}

	certPem := d.Get("certificate").(string)
	keyPem := d.Get("private_key").(string)

	certs := []*x509.Certificate{}

	for _, block := range findBlocksByType([]byte(certPem), "CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return diag.Errorf("failed to parse certificate: %v", err)
		}

		certs = append(certs, cert)
	}

	keyBlock, _ := pem.Decode([]byte(keyPem))

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return diag.Errorf("failed to parse private key: %v", err)
	}

	b, err := pkcs12.Encode(rand.Reader, key, certs[0], certs[1:], password)
	if err != nil {
		return diag.Errorf("failed to encode PKCS12 archive: %v", err)
	}

	d.SetId(certs[0].SerialNumber.String())
	d.Set("archive", base64.StdEncoding.EncodeToString(b))

	return nil
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
