package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceArchive_From(t *testing.T) {
	cert, key := testAccFixturePEM(t)

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
	cert, key := testAccFixture(t)

	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV5ProviderFactories: protoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceArchive_to,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckArchive("data.pkcs12_archive.to_p12", "archive", "", cert, key),
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
