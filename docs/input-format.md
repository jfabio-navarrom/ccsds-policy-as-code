# Input format: `SecurityAssociationDatabase`

One YAML (or JSON) file per mission. Field names follow CCSDS 355.0-B-2 Table 6-1.

```yaml
apiVersion: sdls.portfolio/v1
kind: SecurityAssociationDatabase
metadata:
  mission: DEMOSAT-1
  legacy_implementation: false     # true = pre-Issue-2 implementation (352.0-B-2 §3.2.2)

virtual_channels:
  - name: tc-commands
    protocol: TC                   # TC | TM | AOS | USLP
    gvcid: { tfvn: 0, scid: 42, vcid: 0 }
    carries: telecommand           # telecommand | telemetry | payload | idle_only
    cop: true                      # COP-1 / COP-P in use on this VC

security_associations:
  - spi: 1                         # 1..65534
    protocol: TC
    gvcids: [ { tfvn: 0, scid: 42, vcid: 0 } ]
    service: authenticated_encryption   # authentication | encryption | authenticated_encryption
    algorithm:
      cipher: AES                  # encryption / AE
      mode: GCM                    # CTR | GCM
      key_bits: 256
      # for authentication-only SAs instead:
      # mac: HMAC | CMAC | GMAC
      # hash: SHA-256 | SHA-384 | SHA-512
      # alternative_hash_agreed: true   # needed for SHA-384/512
      # truncation_agreed: true         # needed if mac_length < digest size
    iv_length_octets: 12           # 1..32 when encrypting
    sequence_number:
      length_octets: 4             # 2..8 when authenticating
      window: 5                    # > 0 when authenticating
    pad_length_octets: 0
    mac_length_octets: 16          # 8..64 when authenticating, 0 otherwise
    key_ref: kms://demosat-1/sdls/tc-ae-01   # never key material
```

A Global VC is identified by protocol + TFVN + SCID + VCID, because a TC VC 0
and a TM VC 0 share the numeric GVCID but are different channels.
