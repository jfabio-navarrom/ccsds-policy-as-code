package tests.crypto_mission_test

import data.crypto.algorithms
import data.mission.protection
import data.tests.fixtures as fx
import rego.v1

# --- baseline ---------------------------------------------------------------

test_baseline_has_no_crypto_or_mission_findings if {
	count(algorithms.deny) == 0 with input as fx.base
	count(algorithms.warn) == 0 with input as fx.base
	count(protection.deny) == 0 with input as fx.base
}

# --- CRYPTO-001: AES --------------------------------------------------------

test_crypto_001_rejects_non_aes_cipher if {
	"CRYPTO-001" in fx.ids(algorithms.deny) with input as fx.with_enc({"algorithm": {"cipher": "ChaCha20", "mode": "CTR", "key_bits": 256}})
}

# --- CRYPTO-002: key size ---------------------------------------------------

test_crypto_002_rejects_128_bit_key_on_new_implementation if {
	fx.ids(algorithms.deny) == {"CRYPTO-002"} with input as fx.with_tc({"algorithm": {"cipher": "AES", "mode": "GCM", "key_bits": 128}})
}

test_crypto_002_allows_128_bit_key_on_legacy_but_warns if {
	db := fx.db_with([object.union(fx.tc_ae, {"algorithm": {"cipher": "AES", "mode": "GCM", "key_bits": 128}}), fx.tm_auth], true)
	count(algorithms.deny) == 0 with input as db
	fx.ids(algorithms.warn) == {"CRYPTO-002"} with input as db
}

test_crypto_002_rejects_odd_key_size_even_on_legacy if {
	db := fx.db_with([object.union(fx.tc_ae, {"algorithm": {"cipher": "AES", "mode": "GCM", "key_bits": 64}})], true)
	"CRYPTO-002" in fx.ids(algorithms.deny) with input as db
}

test_crypto_002_applies_to_cmac if {
	cmac := {"algorithm": {"mac": "CMAC", "key_bits": 128}, "mac_length_octets": 16}
	"CRYPTO-002" in fx.ids(algorithms.deny) with input as fx.with_tm(cmac)
}

# --- CRYPTO-003: CTR for encryption-only (warning) -------------------------

test_crypto_003_warns_on_cbc if {
	fx.ids(algorithms.warn) == {"CRYPTO-003"} with input as fx.with_enc({"algorithm": {"cipher": "AES", "mode": "CBC", "key_bits": 256}})
	count(algorithms.deny) == 0 with input as fx.with_enc({"algorithm": {"cipher": "AES", "mode": "CBC", "key_bits": 256}})
}

# --- CRYPTO-004: GCM and 128-bit tag ----------------------------------------

test_crypto_004_rejects_authenticated_encryption_without_gcm if {
	fx.ids(algorithms.deny) == {"CRYPTO-004"} with input as fx.with_tc({"algorithm": {"cipher": "AES", "mode": "CCM", "key_bits": 256}})
}

test_crypto_004_rejects_truncated_gcm_tag if {
	fx.ids(algorithms.deny) == {"CRYPTO-004"} with input as fx.with_tc({"mac_length_octets": 12})
}

# --- CRYPTO-005: authentication algorithms ----------------------------------

test_crypto_005_rejects_sha1 if {
	fx.ids(algorithms.deny) == {"CRYPTO-005"} with input as fx.with_tm({"algorithm": {"mac": "HMAC", "hash": "SHA-1", "key_bits": 256}, "mac_length_octets": 20})
}

test_crypto_005_rejects_unknown_mac if {
	"CRYPTO-005" in fx.ids(algorithms.deny) with input as fx.with_tm({"algorithm": {"mac": "CRC32"}})
}

test_crypto_005_requires_agreement_for_sha512 if {
	sha512 := {"algorithm": {"mac": "HMAC", "hash": "SHA-512", "key_bits": 256}, "mac_length_octets": 64}
	fx.ids(algorithms.deny) == {"CRYPTO-005"} with input as fx.with_tm(sha512)

	agreed := {"algorithm": {"mac": "HMAC", "hash": "SHA-512", "key_bits": 256, "alternative_hash_agreed": true}, "mac_length_octets": 64}
	count(algorithms.deny) == 0 with input as fx.with_tm(agreed)
}

test_crypto_005_allows_cmac_256 if {
	count(algorithms.deny) == 0 with input as fx.with_tm({"algorithm": {"mac": "CMAC", "key_bits": 256}, "mac_length_octets": 16})
}

# --- CRYPTO-006: HMAC truncation ---------------------------------------------

test_crypto_006_rejects_unagreed_truncation if {
	fx.ids(algorithms.deny) == {"CRYPTO-006"} with input as fx.with_tm({"mac_length_octets": 16})
}

test_crypto_006_warns_on_agreed_truncation if {
	agreed := {"algorithm": {"mac": "HMAC", "hash": "SHA-256", "key_bits": 256, "truncation_agreed": true}, "mac_length_octets": 16}
	count(algorithms.deny) == 0 with input as fx.with_tm(agreed)
	fx.ids(algorithms.warn) == {"CRYPTO-006"} with input as fx.with_tm(agreed)
}

# --- MISSION-001: telecommand authenticated ---------------------------------

test_mission_001_rejects_unprotected_tc_vc if {
	fx.ids(protection.deny) == {"MISSION-001"} with input as fx.db([fx.tm_auth, fx.tm_enc])
}

test_mission_001_rejects_encryption_only_tc if {
	enc_only := object.union(fx.tc_ae, {"service": "encryption", "algorithm": {"cipher": "AES", "mode": "CTR", "key_bits": 256}, "mac_length_octets": 0})
	fx.ids(protection.deny) == {"MISSION-001"} with input as fx.db([enc_only, fx.tm_auth])
}

test_mission_001_accepts_authentication_only_tc if {
	auth_only := object.union(fx.tm_auth, {"spi": 2, "protocol": "TC", "gvcids": [{"tfvn": 0, "scid": 1, "vcid": 0}]})
	count(protection.deny) == 0 with input as fx.db([auth_only, fx.tm_auth])
}

# --- MISSION-002: key references ---------------------------------------------

test_mission_002_rejects_inline_key if {
	"MISSION-002" in fx.ids(protection.deny) with input as fx.with_tc({"key_hex": "00112233"})
}

test_mission_002_rejects_file_key_ref if {
	fx.ids(protection.deny) == {"MISSION-002"} with input as fx.with_tc({"key_ref": "file:///etc/keys/tc.key"})
}

test_mission_002_rejects_missing_key_ref if {
	fx.ids(protection.deny) == {"MISSION-002"} with input as fx.db([object.remove(fx.tc_ae, ["key_ref"]), fx.tm_auth])
}

test_mission_002_accepts_pkcs11_ref if {
	count(protection.deny) == 0 with input as fx.with_tc({"key_ref": "pkcs11://slot0/tc"})
}

# --- fail-closed behaviour on missing fields --------------------------------

test_crypto_001_fails_closed_on_missing_cipher if {
	"CRYPTO-001" in fx.ids(algorithms.deny) with input as fx.with_enc({"algorithm": {"mode": "CTR", "key_bits": 256}})
}

test_crypto_004_fails_closed_on_missing_mode if {
	"CRYPTO-004" in fx.ids(algorithms.deny) with input as fx.with_tc({"algorithm": {"cipher": "AES", "key_bits": 256}})
}

test_crypto_005_fails_closed_on_missing_hash if {
	"CRYPTO-005" in fx.ids(algorithms.deny) with input as fx.with_tm({"algorithm": {"mac": "HMAC", "key_bits": 256}})
}

test_crypto_005_fails_closed_on_missing_mac if {
	"CRYPTO-005" in fx.ids(algorithms.deny) with input as fx.with_tm({"algorithm": {"key_bits": 256}})
}
