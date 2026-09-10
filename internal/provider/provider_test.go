package provider

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"software.sslmate.com/src/go-pkcs12"
)

var protoV5ProviderFactories = map[string]func() (tfprotov5.ProviderServer, error){
	"pkcs12": func() (tfprotov5.ProviderServer, error) {
		return Server(context.Background(), "dev")
	},
}

// echoProviderFactories exposes the echo provider, which copies its configuration into the
// state of an echo resource. Ephemeral data is otherwise unobservable from a test.
var echoProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"echo": echoprovider.NewProviderServer(),
}

func TestProvider(t *testing.T) {
	if err := New("dev")().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}

	if _, err := Server(context.Background(), "dev"); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func testAccPreCheck(t *testing.T) {}

// testAccFixturePEM reads the certificate and private key fixtures.
func testAccFixturePEM(t *testing.T) (certificate, privateKey []byte) {
	t.Helper()

	certificate, err := os.ReadFile("./fixtures/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err = os.ReadFile("./fixtures/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	return certificate, privateKey
}

// testAccFixture parses the certificate and private key fixtures.
func testAccFixture(t *testing.T) (*x509.Certificate, any) {
	t.Helper()

	certificatePEM, privateKeyPEM := testAccFixturePEM(t)

	certificateBlock, _ := pem.Decode(certificatePEM)
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)

	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return certificate, privateKey
}

// testAccCheckArchive decodes the base64 PKCS12 archive held in attr and asserts that it
// carries cert and key.
func testAccCheckArchive(n, attr, password string, cert *x509.Certificate, key any) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Can't find %s", n)
		}

		p12, err := base64.StdEncoding.DecodeString(rs.Primary.Attributes[attr])
		if err != nil {
			return fmt.Errorf("Error decoding p12: %s", err)
		}

		pKey, pCert, err := pkcs12.Decode(p12, password)
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
