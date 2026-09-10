# The password, the private key, and the archive are never written to Terraform state.
ephemeral "pkcs12_archive" "client" {
  archive  = filebase64("./client.p12")
  password = var.archive_password
}

# Ephemeral values can be referenced from provider configuration, from other ephemeral
# resources, and from provisioner and connection blocks. They cannot be used in outputs
# or in ordinary resource arguments.
provider "kubernetes" {
  host = var.kubernetes_host

  client_certificate = ephemeral.pkcs12_archive.client.certificate
  client_key         = ephemeral.pkcs12_archive.client.private_key
}

# Setting certificate and private_key encodes a new archive instead of reading one.
ephemeral "pkcs12_archive" "bundle" {
  certificate = file("./cert.pem")
  private_key = file("./key.pem")
  password    = var.archive_password
}

# Write-only arguments also accept ephemeral values, starting in Terraform 1.11.
resource "aws_secretsmanager_secret_version" "bundle" {
  secret_id                = aws_secretsmanager_secret.bundle.id
  secret_string_wo         = ephemeral.pkcs12_archive.bundle.archive
  secret_string_wo_version = 1
}
