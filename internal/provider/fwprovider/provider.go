// Package fwprovider serves the parts of the pkcs12 provider that terraform-plugin-sdk
// cannot express, currently the ephemeral pkcs12_archive resource.
package fwprovider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.ProviderWithEphemeralResources = (*pkcs12Provider)(nil)

type pkcs12Provider struct {
	version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &pkcs12Provider{version: version}
	}
}

func (p *pkcs12Provider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pkcs12"
	resp.Version = p.version
}

func (p *pkcs12Provider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

func (p *pkcs12Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

func (p *pkcs12Provider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return nil
}

func (p *pkcs12Provider) Resources(ctx context.Context) []func() resource.Resource {
	return nil
}

func (p *pkcs12Provider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		newArchiveEphemeralResource,
	}
}
