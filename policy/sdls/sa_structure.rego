# METADATA
# title: SDLS Security Association structure
# description: >-
#   Every SA in the managed-parameter database must be fully and
#   unambiguously defined, otherwise sender and receiver cannot agree
#   on how to process a frame.
# custom:
#   standard: CCSDS 355.0-B-2 (Space Data Link Security Protocol)
package sdls.sa_structure

import data.lib.sdls
import rego.v1

mandatory_fields := ["spi", "iv_length_octets", "sequence_number", "pad_length_octets", "mac_length_octets"]

# METADATA
# title: SDLS-001 Exactly one cryptographic function per SA
# custom:
#   id: SDLS-001
#   clause: CCSDS 355.0-B-2 §4.2.2.4
#   severity: high
deny contains f if {
	some sa in sdls.security_associations
	not object.get(sa, "service", null) in sdls.valid_services
	f := sdls.finding("SDLS-001", "CCSDS 355.0-B-2 §4.2.2.4", sa, sprintf(
		"service must be exactly one of %v, got %v",
		[sort(sdls.valid_services), object.get(sa, "service", null)],
	))
}

# METADATA
# title: SDLS-002 Mandatory SA managed parameters present
# custom:
#   id: SDLS-002
#   clause: CCSDS 355.0-B-2 §4.2.2.5
#   severity: high
deny contains f if {
	some sa in sdls.security_associations
	some field in mandatory_fields
	not field in object.keys(sa)
	f := sdls.finding("SDLS-002", "CCSDS 355.0-B-2 §4.2.2.5", sa, sprintf("missing mandatory parameter '%s'", [field]))
}

# METADATA
# title: SDLS-003 SPI within the managed range
# custom:
#   id: SDLS-003
#   clause: CCSDS 355.0-B-2 Table 6-1 (SPI 1..65534)
#   severity: high
deny contains f if {
	some sa in sdls.security_associations
	not valid_spi(sa.spi)
	f := sdls.finding("SDLS-003", "CCSDS 355.0-B-2 Table 6-1", sa, "SPI must be an integer in 1..65534 (0 and 65535 are outside the managed range)")
}

valid_spi(spi) if {
	is_number(spi)
	spi == round(spi)
	spi >= 1
	spi <= 65534
}

# METADATA
# title: SDLS-004 SPI uniquely identifies one SA
# custom:
#   id: SDLS-004
#   clause: CCSDS 355.0-B-2 §4.2.2.3
#   severity: high
deny contains f if {
	some i, a in sdls.security_associations
	some j, b in sdls.security_associations
	i < j
	a.spi == b.spi
	a.protocol == b.protocol
	f := sdls.finding("SDLS-004", "CCSDS 355.0-B-2 §4.2.2.3", b, sprintf("SPI %v is already used by another %s SA; an SPI must identify exactly one SA", [b.spi, b.protocol]))
}

# METADATA
# title: SDLS-005 SA bound to at least one Global VC / MAP
# custom:
#   id: SDLS-005
#   clause: CCSDS 355.0-B-2 §4.2.2.2.1
#   severity: high
deny contains f if {
	some sa in sdls.security_associations
	count(object.get(sa, "gvcids", [])) == 0
	f := sdls.finding("SDLS-005", "CCSDS 355.0-B-2 §4.2.2.2.1", sa, "SA must specify one or more Global Virtual Channels (or Global MAP IDs)")
}

# METADATA
# title: SDLS-006 SDLS used only on a supported space data link protocol
# description: >-
#   SDLS applies to TM, TC, AOS and USLP; it is not applicable to
#   Proximity-1. A missing or unknown protocol also means the SA cannot be
#   bound to any channel, so every other check on it would pass vacuously.
# custom:
#   id: SDLS-006
#   clause: CCSDS 355.0-B-2 §1.1, §2.1
#   severity: high
deny contains f if {
	some x in array.concat(sdls.security_associations, sdls.virtual_channels)
	not object.get(x, "protocol", null) in sdls.supported_protocols
	f := sdls.finding("SDLS-006", "CCSDS 355.0-B-2 §1.1", x, sprintf("protocol must be one of %v (SDLS is not applicable to Proximity-1), got %v", [sort(sdls.supported_protocols), object.get(x, "protocol", null)]))
}
