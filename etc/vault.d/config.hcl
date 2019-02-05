storage "file" {
  path = "/tmp/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_cert_file = "/etc/vault.d/vault.crt"
  tls_key_file = "/etc/vault.d/vault.key"
}

listener "tcp" {
  address   = "10.10.66.11:8200"
  tls_cert_file = "/etc/vault.d/vault.crt"
  tls_key_file = "/etc/vault.d/vault.key"
}
ui = true
api_addr = "https://10.10.66.11:8200"
cluster_addr = "https://10.10.66.11:8201"