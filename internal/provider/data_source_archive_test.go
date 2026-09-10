package provider

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceArchive_From(t *testing.T) {
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
		ProtoV5ProviderFactories: protoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceArchive_from,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						"data.pkcs12_archive.from_p12", "certificate", string(cert),
					),
					resource.TestCheckResourceAttr(
						"data.pkcs12_archive.from_p12", "private_key", string(key),
					),
				),
			},
		},
	})
}

func TestAccDataSourceArchive_To(t *testing.T) {
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
		ProtoV5ProviderFactories: protoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceArchive_to,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckArchive("data.pkcs12_archive.to_p12", "archive", cert, key),
				),
			},
		},
	})
}

const testAccDataSourceArchive_from = `
data "pkcs12_archive" "from_p12" {
  archive = filebase64("fixtures/archive.p12")
	password = ""
}
`

const testAccDataSourceArchive_to = `
data "pkcs12_archive" "to_p12" {
  certificate = file("fixtures/cert.pem")
	private_key = file("fixtures/key.pem")
	password = ""
}
`
