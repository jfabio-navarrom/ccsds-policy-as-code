# METADATA
# title: SDLS Security Header and Trailer format
# description: >-
#   Field lengths are fixed for the life of an SA and must fit inside the
#   transfer frame. Out-of-range values break interoperability between the
#   ground and on-board crypto implementations.
# custom:
#   standard: CCSDS 355.0-B-2 (Space Data Link Security Protocol)
package sdls.frame_format

import data.lib.sdls
import rego.v1

spi_octets := 2

# METADATA
# title: SDLS-030 Encrypting SAs define an IV of 1..32 octets
# custom:
#   id: SDLS-030
#   clause: CCSDS 355.0-B-2 Table 6-1 (IV 1..32 octets)
#   severity: high
deny contains f if {
	some sa in sdls.security_associations
	sdls.provides_encryption(sa)
	iv := object.get(sa, "iv_length_octets", 0)
	not between(iv, 1, 32)
	f := sdls.finding("SDLS-030", "CCSDS 355.0-B-2 Table 6-1", sa, sprintf("encrypting SA needs an IV field of 1..32 octets, got %v", [iv]))
}

# METADATA
# title: SDLS-031 Security Trailer (MAC) present iff the SA authenticates
# custom:
#   id: SDLS-031
#   clause: CCSDS 355.0-B-2 §4.1.2.2, §4.1.2.3; Table 6-1 (MAC 8..64 octets)
#   severity: high
deny contains f if {
	some sa in sdls.security_associations
	sdls.provides_authentication(sa)
	mac := object.get(sa, "mac_length_octets", 0)
	not between(mac, 8, 64)
	f := sdls.finding("SDLS-031", "CCSDS 355.0-B-2 §4.1.2.2, Table 6-1", sa, sprintf("authenticating SA needs a MAC of 8..64 octets in the Security Trailer, got %v", [mac]))
}

deny contains f if {
	some sa in sdls.security_associations
	sa.service == "encryption"
	mac := object.get(sa, "mac_length_octets", 0)
	mac != 0
	f := sdls.finding("SDLS-031", "CCSDS 355.0-B-2 §4.1.2.2", sa, sprintf("encryption-only SA declares a %v-octet MAC; it produces no Security Trailer (did you mean authenticated_encryption?)", [mac]))
}

# METADATA
# title: SDLS-032 Security Header no larger than 64 octets
# custom:
#   id: SDLS-032
#   clause: CCSDS 355.0-B-2 §4.1.1.1.4
#   severity: medium
deny contains f if {
	some sa in sdls.security_associations
	size := header_octets(sa)
	size > 64
	f := sdls.finding("SDLS-032", "CCSDS 355.0-B-2 §4.1.1.1.4", sa, sprintf("Security Header would be %v octets (SPI %v + IV + sequence number + pad length); the limit is 64", [size, spi_octets]))
}

header_octets(sa) := ((spi_octets + object.get(sa, "iv_length_octets", 0)) + object.get(object.get(sa, "sequence_number", {}), "length_octets", 0)) + object.get(sa, "pad_length_octets", 0)

between(x, lo, hi) if {
	is_number(x)
	x >= lo
	x <= hi
}
