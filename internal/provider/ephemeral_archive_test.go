package provider

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

// ephemeralVersionChecks gates the ephemeral resource tests on the Terraform release that
// introduced ephemeral resources.
var ephemeralVersionChecks = []tfversion.TerraformVersionCheck{
	tfversion.SkipBelow(tfversion.Version1_10_0),
}

func TestAccEphemeralArchive_From(t *testing.T) {
	cert, err := os.ReadFile("./fixtures/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	key, err := os.ReadFile("./fixtures/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   ephemeralVersionChecks,
		ProtoV5ProviderFactories: protoV5ProviderFactories,
		ProtoV6ProviderFactories: echoProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEphemeralArchive_from,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("echo.test", "data.certificate", string(cert)),
					resource.TestCheckResourceAttr("echo.test", "data.private_key", string(key)),
				),
			},
		},
	})
}

func TestAccEphemeralArchive_To(t *testing.T) {
	certBytes, err := os.ReadFile("./fixtures/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	keyBytes, err := os.ReadFile("./fixtures/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	certBlock, _ := pem.Decode(certBytes)
	keyBlock, _ := pem.Decode(keyBytes)

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   ephemeralVersionChecks,
		ProtoV5ProviderFactories: protoV5ProviderFactories,
		ProtoV6ProviderFactories: echoProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEphemeralArchive_to,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckArchive("echo.test", "data.archive", cert, key),
				),
			},
		},
	})
}

const testAccEphemeralArchive_from = `
ephemeral "pkcs12_archive" "from_p12" {
  archive  = filebase64("fixtures/archive.p12")
  password = ""
}

provider "echo" {
  data = ephemeral.pkcs12_archive.from_p12
}

resource "echo" "test" {}
`

const testAccEphemeralArchive_to = `
ephemeral "pkcs12_archive" "to_p12" {
  certificate = file("fixtures/cert.pem")
  private_key = file("fixtures/key.pem")
  password    = ""
}

provider "echo" {
  data = ephemeral.pkcs12_archive.to_p12
}

resource "echo" "test" {}
`
