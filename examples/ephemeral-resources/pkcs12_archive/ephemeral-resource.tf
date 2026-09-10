# Read the certificate and private key out of an archive. Neither they nor the password
# are written to Terraform state.
ephemeral "pkcs12_archive" "client" {
  archive  = filebase64("./client.p12")
  password = var.archive_password
}

# Ephemeral values can be passed to provider configuration, to write-only resource
# arguments, and to other ephemeral resources. They cannot be used in outputs or in
# ordinary resource arguments.
provider "kubernetes" {
  host = var.kubernetes_host

  client_certificate = ephemeral.pkcs12_archive.client.certificate
  client_key         = ephemeral.pkcs12_archive.client.private_key
}

# Build a new archive from PEM certificates and keys.
ephemeral "pkcs12_archive" "bundle" {
  certificate = file("./cert.pem")
  private_key = file("./key.pem")
  password    = var.archive_password
}
