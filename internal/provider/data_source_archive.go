package provider

import (
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
		// This description is used by the documentation generator and the language server.
		Description: "Sample data source in the Terraform provider scaffolding.",

		ReadContext: dataSourceArchiveRead,

		Schema: map[string]*schema.Schema{
			"archive": {
				Description:  "The PKCS12 archive",
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
				Description: "The certificate in PEM format",
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

		key, cert, err := pkcs12.Decode(archive, password)
		if err != nil {
			return diag.Errorf("failed to decode PKCS12 archive: %v", err)
		}

		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return diag.Errorf("failed to marshal private key: %v", err)
		}

		d.Set("private_key", string(pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})))

		d.Set("certificate", string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})))

		d.SetId(cert.SerialNumber.String())
		return nil
	}

	certPem := d.Get("certificate").(string)
	keyPem := d.Get("private_key").(string)

	certBlock, _ := pem.Decode([]byte(certPem))
	keyBlock, _ := pem.Decode([]byte(keyPem))

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return diag.Errorf("failed to parse certificate: %v", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return diag.Errorf("failed to parse private key: %v", err)
	}

	caCerts := []*x509.Certificate{} // TODO: support CA certs

	b, err := pkcs12.Encode(rand.Reader, key, cert, caCerts, password)
	if err != nil {
		return diag.Errorf("failed to encode PKCS12 archive: %v", err)
	}

	d.SetId(cert.SerialNumber.String())
	d.Set("archive", base64.StdEncoding.EncodeToString(b))

	return nil
}
