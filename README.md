# Terraform Provider PKCS12

A Terraform provider for working with [PKCS #12](https://en.wikipedia.org/wiki/PKCS_12) archives. Extract certificates and keys from an archive or create a new archive from PEM-formatted certificates and keys.

The `pkcs12_archive` [ephemeral resource](docs/ephemeral-resources/archive.md) does this without persisting the password, the private key, or the archive to state. It requires Terraform 1.10 or later, and its attributes can only be referenced from provider configuration, write-only resource arguments, and other ephemeral resources.

The `pkcs12_archive` [data source](docs/data-sources/archive.md) does the same conversion where those restrictions don't fit. Terraform writes every attribute of a data source to state, including the password.
