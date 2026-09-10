# Terraform Provider PKCS12

A Terraform provider for working with [PKCS #12](https://en.wikipedia.org/wiki/PKCS_12) archives. Extract certificates and keys from an archive or create a new archive from PEM-formatted certificates and keys.

```terraform
terraform {
  required_providers {
    pkcs12 = {
      source = "bendrucker/pkcs12"
    }
  }
}
```

## Ephemeral Resource

The `pkcs12_archive` [ephemeral resource](docs/ephemeral-resources/archive.md) converts an archive without writing the password, the private key, or the archive to state. It requires Terraform 1.10 or later. Its attributes can only be referenced from contexts that Terraform never writes to state, including provider configuration, other ephemeral resources, and `provisioner` and `connection` blocks. Write-only resource arguments accept them starting in Terraform 1.11.

## Data Source

The `pkcs12_archive` [data source](docs/data-sources/archive.md) performs the same conversion when those restrictions get in the way. Terraform writes every attribute of a data source to state, including the password.
