# METADATA
# title: SDLS anti-replay
# description: >-
#   An authenticated telecommand without a sequence number can be recorded
#   and replayed verbatim: the MAC stays valid. SDLS defends against this
#   with an anti-replay sequence number and a receive window.
# custom:
#   standard: CCSDS 355.0-B-2 (Space Data Link Security Protocol)
package sdls.anti_replay

import data.lib.sdls
import rego.v1

# METADATA
# title: SDLS-020 Authenticating SAs carry an anti-replay sequence number
# custom:
#   id: SDLS-020
#   clause: CCSDS 355.0-B-2 §4.2.2.6.1; Table 6-1 (2..8 octets)
#   severity: critical
deny contains f if {
	some sa in sdls.security_associations
	sdls.provides_authentication(sa)
	length := object.get(object.get(sa, "sequence_number", {}), "length_octets", 0)
	not in_range(length, 2, 8)
	f := sdls.finding("SDLS-020", "CCSDS 355.0-B-2 §4.2.2.6.1, Table 6-1", sa, sprintf("authenticating SA needs an anti-replay sequence number of 2..8 octets, got %v", [length]))
}

# METADATA
# title: SDLS-021 Authenticating SAs define a positive sequence number window
# custom:
#   id: SDLS-021
#   clause: CCSDS 355.0-B-2 §4.2.2.6.1; Table 6-1 (window > 0)
#   severity: critical
deny contains f if {
	some sa in sdls.security_associations
	sdls.provides_authentication(sa)
	window := object.get(object.get(sa, "sequence_number", {}), "window", 0)
	not window > 0
	f := sdls.finding("SDLS-021", "CCSDS 355.0-B-2 §4.2.2.6.1, Table 6-1", sa, sprintf("sequence number window must be a positive integer, got %v", [window]))
}

# METADATA
# title: SDLS-022 Telecommand anti-replay window should stay tight
# description: >-
#   Mission-profile guidance, not a CCSDS limit: a wide window on an uplink
#   widens the set of stale frames the receiver will accept. Reported as a
#   warning so the mission can justify the value.
# custom:
#   id: SDLS-022
#   clause: Mission profile (hardening of CCSDS 355.0-B-2 §2.3.2.3.3)
#   severity: low
warn contains f if {
	some sa in sdls.security_associations
	sa.protocol == "TC"
	sdls.provides_authentication(sa)
	window := sa.sequence_number.window
	window > data.mission_profile.max_tc_window
	f := sdls.finding("SDLS-022", "mission profile, hardens CCSDS 355.0-B-2 §2.3.2.3.3", sa, sprintf("TC window %v is above the mission profile maximum of %v", [window, data.mission_profile.max_tc_window]))
}

in_range(x, lo, hi) if {
	is_number(x)
	x >= lo
	x <= hi
}
