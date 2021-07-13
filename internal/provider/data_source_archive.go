package provider

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/pkcs12"
)

func dataSourceArchive() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Sample data source in the Terraform provider scaffolding.",

		ReadContext: dataSourceArchiveRead,

		Schema: map[string]*schema.Schema{
			"archive": {
				Description:   "The PKCS12 archive",
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"certificate", "private_key"},
				Computed:      true,
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
	}

	return nil
}
