package fwprovider

import (
	"context"
	"encoding/base64"

	"github.com/bendrucker/terraform-provider-pkcs12/internal/archive"
	"github.com/hashicorp/terraform-plugin-framework-validators/ephemeralvalidator"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResourceWithConfigValidators = (*archiveEphemeralResource)(nil)

type archiveEphemeralResource struct{}

func newArchiveEphemeralResource() ephemeral.EphemeralResource {
	return &archiveEphemeralResource{}
}

type archiveModel struct {
	Archive     types.String `tfsdk:"archive"`
	Password    types.String `tfsdk:"password"`
	Certificate types.String `tfsdk:"certificate"`
	PrivateKey  types.String `tfsdk:"private_key"`
}

func (e *archiveEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_archive"
}

func (e *archiveEphemeralResource) Schema(ctx context.Context, req ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Read the content of a PKCS12 archive or create a new archive by specifying its content, " +
			"without writing the password, the private key, or the archive to Terraform state.\n\n" +
			"Ephemeral resources are only available in Terraform 1.10 and later, and their attributes can only be " +
			"referenced from other ephemeral resources, provider configuration, and write-only resource arguments.",

		Attributes: map[string]schema.Attribute{
			"archive": schema.StringAttribute{
				MarkdownDescription: "The PKCS12 archive, base64 encoded",
				Optional:            true,
				Computed:            true,
				Sensitive:           true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "The password for the PKCS12 archive",
				Required:            true,
				Sensitive:           true,
			},
			"certificate": schema.StringAttribute{
				MarkdownDescription: "The certificate in PEM format. The leaf certificate should be followed by any CA certificates.",
				Optional:            true,
				Computed:            true,
			},
			"private_key": schema.StringAttribute{
				MarkdownDescription: "The private key in PEM format",
				Optional:            true,
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func (e *archiveEphemeralResource) ConfigValidators(ctx context.Context) []ephemeral.ConfigValidator {
	return []ephemeral.ConfigValidator{
		ephemeralvalidator.ExactlyOneOf(
			path.MatchRoot("archive"),
			path.MatchRoot("certificate"),
		),
		ephemeralvalidator.RequiredTogether(
			path.MatchRoot("certificate"),
			path.MatchRoot("private_key"),
		),
	}
}

func (e *archiveEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var config archiveModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	password := config.Password.ValueString()

	if !config.Archive.IsNull() {
		data, err := base64.StdEncoding.DecodeString(config.Archive.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("archive"), "Invalid PKCS12 archive", "Failed to decode archive as base64: "+err.Error())
			return
		}

		a, err := archive.Decode(data, password)
		if err != nil {
			resp.Diagnostics.AddError("Invalid PKCS12 archive", err.Error())
			return
		}

		config.Certificate = types.StringValue(a.Certificate)
		config.PrivateKey = types.StringValue(a.PrivateKey)
	} else {
		a, err := archive.Parse(config.Certificate.ValueString(), config.PrivateKey.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid certificate or private key", err.Error())
			return
		}

		data, err := a.Encode(password)
		if err != nil {
			resp.Diagnostics.AddError("Invalid PKCS12 archive", err.Error())
			return
		}

		config.Archive = types.StringValue(base64.StdEncoding.EncodeToString(data))
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &config)...)
}
