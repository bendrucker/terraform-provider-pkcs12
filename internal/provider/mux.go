package provider

import (
	"context"

	"github.com/bendrucker/terraform-provider-pkcs12/internal/provider/fwprovider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-mux/tf5muxserver"
)

// Server combines the terraform-plugin-sdk and terraform-plugin-framework halves of the
// provider into the single provider server that Terraform talks to.
func Server(ctx context.Context, version string) (tfprotov5.ProviderServer, error) {
	mux, err := tf5muxserver.NewMuxServer(
		ctx,
		New(version)().GRPCProvider,
		providerserver.NewProtocol5(fwprovider.New(version)()),
	)
	if err != nil {
		return nil, err
	}

	return mux.ProviderServer(), nil
}
