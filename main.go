package main

import (
	"context"
	"flag"
	"log"

	"github.com/bendrucker/terraform-provider-pkcs12/internal/provider"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5/tf5server"
)

// Run "go generate" to format example terraform files and generate the docs for the registry/website

// If you do not have terraform installed, you can remove the formatting command, but its suggested to
// ensure the documentation is formatted properly.
//go:generate terraform fmt -recursive ./examples/

// Run the docs generation tool, check its repository for more information on how it works and how docs
// can be customized.
// The provider name is passed explicitly because tfplugindocs otherwise infers it from the
// working directory name, which is wrong in a git worktree.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name terraform-provider-pkcs12

const address = "registry.terraform.io/bendrucker/pkcs12"

var (
	// these will be set by the goreleaser configuration
	// to appropriate values for the compiled binary
	version string = "dev"

	// goreleaser can also pass the specific commit if you want
	// commit  string = ""
)

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	server, err := provider.Server(context.Background(), version)
	if err != nil {
		log.Fatal(err.Error())
	}

	var opts []tf5server.ServeOpt
	if debugMode {
		opts = append(opts, tf5server.WithManagedDebug())
	}

	if err := tf5server.Serve(address, func() tfprotov5.ProviderServer { return server }, opts...); err != nil {
		log.Fatal(err.Error())
	}
}
