package provider

import (
	"context"
	"encoding/base64"

	"github.com/bendrucker/terraform-provider-pkcs12/internal/archive"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceArchive() *schema.Resource {
	return &schema.Resource{
		Description: "Read the content of a PKCS12 archive or create a new archive by specifying its content.\n\n" +
			"Every attribute of a data source is persisted to Terraform state, including the password. " +
			"Use the `pkcs12_archive` ephemeral resource to keep the password and the archive contents out of state.",

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
				Sensitive:   true,
			},
			"certificate": {
				Description:  "The certificate in PEM format. The leaf certificate should be followed by any CA certificates.",
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"private_key"},
				Computed:     true,
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
		data, err := base64.StdEncoding.DecodeString(v.(string))
		if err != nil {
			return diag.Errorf("failed to decode archive as base64: %v", err)
		}

		a, err := archive.Decode(data, password)
		if err != nil {
			return diag.FromErr(err)
		}

		d.Set("private_key", a.PrivateKey())
		d.Set("certificate", a.Certificate())

		d.SetId(a.Serial())
		return nil
	}

	a, err := archive.Parse(d.Get("certificate").(string), d.Get("private_key").(string))
	if err != nil {
		return diag.FromErr(err)
	}

	data, err := a.Encode(password)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(a.Serial())
	d.Set("archive", base64.StdEncoding.EncodeToString(data))

	return nil
}
