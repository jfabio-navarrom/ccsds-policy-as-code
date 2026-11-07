# METADATA
# title: CCSDS cryptographic algorithm baseline
# description: >-
#   Checks every SA's algorithm choice against the CCSDS Cryptographic
#   Algorithms Blue Book. Where the book says "shall" the rule denies;
#   where it allows a choice that needs a priori agreement between the
#   communicating entities, the rule denies unless that agreement is
#   recorded in the SA, and otherwise warns.
# custom:
#   standard: CCSDS 352.0-B-2 (CCSDS Cryptographic Algorithms)
package crypto.algorithms

import data.lib.sdls
import rego.v1

hmac_digest_octets := {"SHA-256": 32, "SHA-384": 48, "SHA-512": 64}

alg(sa) := object.get(sa, "algorithm", {})

# Fail closed: a missing field reads as null, so a rule like
# `cipher != "AES"` still fires instead of silently becoming undefined.
param(sa, name) := object.get(alg(sa), name, null)

# METADATA
# title: CRYPTO-001 Encryption uses AES
# custom:
#   id: CRYPTO-001
#   clause: CCSDS 352.0-B-2 §3.1
#   severity: critical
deny contains f if {
	some sa in sdls.security_associations
	sdls.provides_encryption(sa)
	param(sa, "cipher") != "AES"
	f := sdls.finding("CRYPTO-001", "CCSDS 352.0-B-2 §3.1", sa, sprintf("encryption must use AES, got %v", [param(sa, "cipher")]))
}

# METADATA
# title: CRYPTO-002 256-bit keys for new implementations
# description: >-
#   New implementations shall use 256-bit AES keys. Implementations that
#   predate Issue 2 may keep 128-bit keys (CMAC: 128/192/256). Set
#   metadata.legacy_implementation to claim that allowance; it is reported.
# custom:
#   id: CRYPTO-002
#   clause: CCSDS 352.0-B-2 §3.2.1, §3.2.2, §4.3.1.1, §4.3.1.2
#   severity: high
deny contains f if {
	some sa in sdls.security_associations
	uses_aes(sa)
	bits := object.get(alg(sa), "key_bits", 0)
	not key_size_ok(bits)
	f := sdls.finding("CRYPTO-002", "CCSDS 352.0-B-2 §3.2, §4.3.1", sa, key_msg(bits))
}

uses_aes(sa) if param(sa, "cipher") == "AES"

uses_aes(sa) if param(sa, "mac") == "CMAC"

key_size_ok(bits) if bits == 256

key_size_ok(bits) if {
	sdls.legacy
	bits in {128, 192}
}

key_msg(bits) := sprintf("new implementations shall use a 256-bit AES key, got %v", [bits]) if not sdls.legacy

key_msg(bits) := sprintf("legacy implementations may use 128 (CMAC: 128/192) or 256-bit keys, got %v", [bits]) if sdls.legacy

warn contains f if {
	sdls.legacy
	some sa in sdls.security_associations
	uses_aes(sa)
	param(sa, "key_bits") != 256
	f := sdls.finding("CRYPTO-002", "CCSDS 352.0-B-2 §3.2.2", sa, sprintf("running on the legacy allowance with a %v-bit key; plan migration to 256-bit", [param(sa, "key_bits")]))
}

# METADATA
# title: CRYPTO-003 Encryption-only SAs use Counter Mode
# description: >-
#   §3.3 makes CTR the CCSDS mode; other modes are permitted but "should be
#   carefully considered", so a non-CTR mode is a warning, not a failure.
# custom:
#   id: CRYPTO-003
#   clause: CCSDS 352.0-B-2 §3.3
#   severity: medium
warn contains f if {
	some sa in sdls.security_associations
	sa.service == "encryption"
	param(sa, "mode") != "CTR"
	f := sdls.finding("CRYPTO-003", "CCSDS 352.0-B-2 §3.3", sa, sprintf("CCSDS implementations use Counter Mode; %v needs a documented justification", [param(sa, "mode")]))
}

# METADATA
# title: CRYPTO-004 Authenticated encryption uses AES-GCM with a 128-bit tag
# custom:
#   id: CRYPTO-004
#   clause: CCSDS 352.0-B-2 §3.4.1, §3.4.2
#   severity: critical
deny contains f if {
	some sa in sdls.security_associations
	sa.service == "authenticated_encryption"
	param(sa, "mode") != "GCM"
	f := sdls.finding("CRYPTO-004", "CCSDS 352.0-B-2 §3.4.1", sa, sprintf("authenticated encryption shall use GCM, got %v", [param(sa, "mode")]))
}

deny contains f if {
	some sa in sdls.security_associations
	sa.service == "authenticated_encryption"
	sa.mac_length_octets != 16
	f := sdls.finding("CRYPTO-004", "CCSDS 352.0-B-2 §3.4.2", sa, sprintf("the GCM tag shall be 128 bits (16 octets), got %v octets", [sa.mac_length_octets]))
}

# METADATA
# title: CRYPTO-005 Authentication-only SAs use HMAC-SHA-2 or AES-CMAC/GMAC
# custom:
#   id: CRYPTO-005
#   clause: CCSDS 352.0-B-2 §4.2.2, §4.3
#   severity: critical
deny contains f if {
	some sa in sdls.security_associations
	sa.service == "authentication"
	not param(sa, "mac") in {"HMAC", "CMAC", "GMAC"}
	f := sdls.finding("CRYPTO-005", "CCSDS 352.0-B-2 §4.2, §4.3", sa, sprintf("authentication must use HMAC (FIPS 198-1) or a cipher-based MAC (CMAC, or GMAC), got %v", [param(sa, "mac")]))
}

deny contains f if {
	some sa in sdls.security_associations
	param(sa, "mac") == "HMAC"
	param(sa, "hash") == "SHA-1"
	f := sdls.finding("CRYPTO-005", "CCSDS 352.0-B-2 §4.2.2.3.2", sa, "SHA-1 shall not be used")
}

deny contains f if {
	some sa in sdls.security_associations
	param(sa, "mac") == "HMAC"
	param(sa, "hash") != "SHA-1"
	not param(sa, "hash") in object.keys(hmac_digest_octets)
	f := sdls.finding("CRYPTO-005", "CCSDS 352.0-B-2 §4.2.2.1", sa, sprintf("HMAC shall use a SHA function from FIPS 180-4 (SHA-256/384/512), got %v", [param(sa, "hash")]))
}

deny contains f if {
	some sa in sdls.security_associations
	param(sa, "mac") == "HMAC"
	param(sa, "hash") in {"SHA-384", "SHA-512"}
	not object.get(alg(sa), "alternative_hash_agreed", false)
	f := sdls.finding("CRYPTO-005", "CCSDS 352.0-B-2 §4.2.2.2, §4.2.2.3.1", sa, sprintf("HMAC normally uses SHA-256; %v must be agreed a priori (set algorithm.alternative_hash_agreed: true)", [param(sa, "hash")]))
}

# METADATA
# title: CRYPTO-006 HMAC output not truncated without prior agreement
# custom:
#   id: CRYPTO-006
#   clause: CCSDS 352.0-B-2 §4.2.3.1, §4.2.3.2
#   severity: medium
deny contains f if {
	some sa in sdls.security_associations
	param(sa, "mac") == "HMAC"
	full := hmac_digest_octets[param(sa, "hash")]
	sa.mac_length_octets < full
	not object.get(alg(sa), "truncation_agreed", false)
	f := sdls.finding("CRYPTO-006", "CCSDS 352.0-B-2 §4.2.3.2", sa, sprintf("HMAC-%v truncated to %v of %v octets without a recorded a-priori agreement (algorithm.truncation_agreed)", [param(sa, "hash"), sa.mac_length_octets, full]))
}

warn contains f if {
	some sa in sdls.security_associations
	param(sa, "mac") == "HMAC"
	full := hmac_digest_octets[param(sa, "hash")]
	sa.mac_length_octets < full
	object.get(alg(sa), "truncation_agreed", false)
	f := sdls.finding("CRYPTO-006", "CCSDS 352.0-B-2 §4.2.3.1", sa, sprintf("HMAC output truncated to %v octets by agreement; CCSDS recommends not truncating", [sa.mac_length_octets]))
}
