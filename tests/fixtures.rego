# Test fixtures: a minimal, fully compliant SA database. Each test mutates
# one thing and asserts that exactly the expected control fires.
package tests.fixtures

import rego.v1

tc_vc := {"name": "tc", "protocol": "TC", "gvcid": {"tfvn": 0, "scid": 1, "vcid": 0}, "carries": "telecommand", "cop": true}

tm_vc := {"name": "tm", "protocol": "TM", "gvcid": {"tfvn": 0, "scid": 1, "vcid": 0}, "carries": "telemetry", "cop": false}

payload_vc := {"name": "payload", "protocol": "TM", "gvcid": {"tfvn": 0, "scid": 1, "vcid": 2}, "carries": "payload", "cop": false}

idle_vc := {"name": "idle", "protocol": "TM", "gvcid": {"tfvn": 0, "scid": 1, "vcid": 7}, "carries": "idle_only", "cop": false}

vcs := [tc_vc, tm_vc, payload_vc, idle_vc]

tc_ae := {
	"spi": 1, "description": "tc ae", "protocol": "TC",
	"gvcids": [{"tfvn": 0, "scid": 1, "vcid": 0}],
	"service": "authenticated_encryption",
	"algorithm": {"cipher": "AES", "mode": "GCM", "key_bits": 256},
	"iv_length_octets": 12,
	"sequence_number": {"length_octets": 4, "window": 5},
	"pad_length_octets": 0, "mac_length_octets": 16,
	"key_ref": "kms://test/tc",
}

tm_auth := {
	"spi": 10, "description": "tm auth", "protocol": "TM",
	"gvcids": [{"tfvn": 0, "scid": 1, "vcid": 0}],
	"service": "authentication",
	"algorithm": {"mac": "HMAC", "hash": "SHA-256", "key_bits": 256},
	"iv_length_octets": 0,
	"sequence_number": {"length_octets": 4, "window": 64},
	"pad_length_octets": 0, "mac_length_octets": 32,
	"key_ref": "hsm://test/tm",
}

tm_enc := {
	"spi": 11, "description": "tm enc", "protocol": "TM",
	"gvcids": [{"tfvn": 0, "scid": 1, "vcid": 2}],
	"service": "encryption",
	"algorithm": {"cipher": "AES", "mode": "CTR", "key_bits": 256},
	"iv_length_octets": 16,
	"sequence_number": {"length_octets": 0, "window": 0},
	"pad_length_octets": 0, "mac_length_octets": 0,
	"key_ref": "kms://test/payload",
}

db_with(sas, legacy) := {
	"metadata": {"mission": "TEST", "legacy_implementation": legacy},
	"virtual_channels": vcs,
	"security_associations": sas,
}

db(sas) := db_with(sas, false)

# Shallow patch: top-level keys in `patch` replace the original value
# entirely (object.union alone would deep-merge nested objects).
patched(obj, patch) := object.union(object.remove(obj, object.keys(patch)), patch)

# Replace one SA in an otherwise compliant database.
with_tc(patch) := db([patched(tc_ae, patch), tm_auth, tm_enc])

with_tm(patch) := db([tc_ae, patched(tm_auth, patch), tm_enc])

with_enc(patch) := db([tc_ae, tm_auth, patched(tm_enc, patch)])

base := db([tc_ae, tm_auth, tm_enc])

ids(findings) := {f.policy_id | some f in findings}
