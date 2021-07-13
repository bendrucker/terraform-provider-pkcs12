data "pkcs12_archive" "from_archive" {
  archive  = filebase64("./archive.p12")
  password = ""
}

output "certificate" {
  value = data.pkcs12_archive.certificate
}

output "private_key" {
  sensitive = true
  value     = data.pkcs12_archive.private_key
}

data "pkcs12_archive" "to_archive" {
  certificate = file("./cert.pem")
  private_key = file("./key.pem") 
  password    = ""
}

resource "local_file" "foo" {
  content_base64 = data.pkcs12_archive.archive
  filename       = "archive.p12"
}
