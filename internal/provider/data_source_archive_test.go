package provider

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"software.sslmate.com/src/go-pkcs12"
)

func TestAccDataSourceArchive_From(t *testing.T) {
	cert, err := ioutil.ReadFile("./fixtures/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	key, err := ioutil.ReadFile("./fixtures/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
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
	certBytes, err := ioutil.ReadFile("./fixtures/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	keyBytes, err := ioutil.ReadFile("./fixtures/key.pem")
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
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceArchive_to,
				Check: resource.ComposeTestCheckFunc(
					testAccDataSourceArchiveCheckP12("data.pkcs12_archive.to_p12", cert, key),
				),
			},
		},
	})
}

func testAccDataSourceArchiveCheckP12(n string, cert *x509.Certificate, key interface{}) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Can't find data source: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		p12, err := base64.StdEncoding.DecodeString(rs.Primary.Attributes["archive"])
		if err != nil {
			return fmt.Errorf("Error decoding p12: %s", err)
		}

		pKey, pCert, err := pkcs12.Decode(p12, rs.Primary.Attributes["password"])
		if err != nil {
			return fmt.Errorf("Error decoding p12: %s", err)
		}

		if !cert.Equal(pCert) {
			return fmt.Errorf("certificate mismatch")
		}

		if !key.(*rsa.PrivateKey).Equal(pKey.(*rsa.PrivateKey)) {
			return fmt.Errorf("private key mismatch")
		}

		return nil
	}
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
