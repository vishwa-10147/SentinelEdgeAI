pid_file = "/var/run/vault-agent.pid"

vault {
  address = "https://vault.example.com:8200"
}

auto_auth {
  # Example using AppRole. Replace or extend with your preferred method.
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "/etc/vault/role_id"
      secret_id_file_path = "/etc/vault/secret_id"
    }
  }
}

cache { }

listener "tcp" {
  # Not required for simple agent usage; uncomment to enable local metrics / telemetry
  # address = "127.0.0.1:8200"
  # tls_disable = true
}

template {
  # Renders the key material into a file that the sentinel service reads.
  source      = "/etc/vault/templates/model_signing.tmpl"
  destination = "/etc/sentinel/model_signing.key"
  perms       = "0600"
}
