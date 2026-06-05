rule ShaiHulud_Setup_JS {
  meta:
    description = "Shai-Hulud supply chain worm - setup.js wrapper and decrypted payload"
    campaign = "Shai-Hulud / Children of Shai-Hulud"
    date = "2026-06-02"

  strings:
    // C2 marker -- present in both wrapper (Layer 1 code) and payload (regex literal)
    $marker = "thebeautifulsnadsoftime" ascii

    // Layer 0/1: setup.js outer wrapper
    $aes_key1 = "e07578058c9f43f4dd29dc7163ca582b" ascii
    $aes_key2 = "492b042f7ec55eb2ac211ac6d128cf2a" ascii
    $bun_dl = "bun-v1.3.13/bun-" ascii
    $rot9 = "fromCharCode((c.charCodeAt(0)-b+n)%26+b)" ascii

    // Layer 2b: decrypted payload -- obfuscation artifacts
    $decoder = "f5a709847" ascii
    $daemon_gate = "__IS_DAEMON" ascii
    $batch_cfg = "flushThresholdBytes" ascii

    // Layer 2b: credential theft indicators
    $oidc_theft = "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ascii
    $imds_header = "X-aws-ec2-metadata-token" ascii
    $vault_header = "X-Vault-Token" ascii
    $gh_token_re = "ghp_[A-Za-z0-9" ascii
    $aws_key_re = "AKIA[0-9A-Z]" ascii

    // Layer 2b: supply chain propagation -- provenance forgery + tar injection
    $sigstore_ts = "signedEntryTimestamp" ascii
    $dsse = "dsseEnvelope" ascii
    $tar_inject = "onWriteEntry" ascii

  condition:
    // Outer wrapper (any layer)
    $marker
    or ($aes_key1 and $aes_key2)
    or ($rot9 and $bun_dl)
    // Inner payload -- obfuscation fingerprint (highly specific combo)
    or ($decoder and $daemon_gate)
    // Inner payload -- credential theft + exfiltration pipeline
    or ($oidc_theft and $imds_header and $batch_cfg)
    // Inner payload -- supply chain worm behavior
    or ($sigstore_ts and $dsse and $tar_inject)
    // Broad catch: enough indicators from any layer
    or (5 of them)
}

rule ShaiHulud_TmpPayload {
  meta:
    description = "Shai-Hulud decrypted payload - optimized for /tmp scanning"
    campaign = "Shai-Hulud / Children of Shai-Hulud"
    date = "2026-06-02"
    usage = "yara shai_hulud.yar /tmp/ -r"

  strings:
    $marker = "thebeautifulsnadsoftime" ascii
    $decoder = "f5a709847" ascii
    $daemon_gate = "__IS_DAEMON" ascii
    $batch_cfg = "flushThresholdBytes" ascii
    $oidc_theft = "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ascii
    $imds_header = "X-aws-ec2-metadata-token" ascii
    $vault_header = "X-Vault-Token" ascii
    $sigstore_ts = "signedEntryTimestamp" ascii
    $dsse = "dsseEnvelope" ascii
    $tar_inject = "onWriteEntry" ascii

  condition:
    // Payload is ~608KB; allow 2x margin for variants but skip multi-MB files
    filesize > 100KB and filesize < 2MB
    and (
      $marker
      or ($decoder and $daemon_gate)
      or ($oidc_theft and $imds_header and $batch_cfg)
      or ($sigstore_ts and $dsse and $tar_inject)
      or (4 of them)
    )
}
