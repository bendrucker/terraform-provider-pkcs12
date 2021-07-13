package provider

import (
	"io/ioutil"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccDataSourceScaffolding(t *testing.T) {
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
				Config: testAccDataSourceArchive,
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

const testAccDataSourceArchive = `
data "pkcs12_archive" "from_p12" {
  archive = filebase64("fixtures/archive.p12")
	password = ""
}
`
