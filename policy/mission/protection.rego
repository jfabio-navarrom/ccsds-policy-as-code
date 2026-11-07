# METADATA
# title: Mission protection profile
# description: >-
#   SDLS is a toolbox: CCSDS does not say which channels a mission must
#   protect. These rules encode the mission's own decisions, justified by
#   the threats CCSDS catalogues in its informational Green Books.
# custom:
#   standard: Mission profile, rationale from CCSDS 350.1-G (Security Threats against Space Missions)
package mission.protection

import data.lib.sdls
import data.mission_profile
import rego.v1

# METADATA
# title: MISSION-001 Every telecommand VC is authenticated
# description: >-
#   An unauthenticated uplink lets anyone with a transmitter in view of the
#   spacecraft send commands. Encryption alone is not enough: CTR-mode
#   ciphertext can be modified bit by bit without detection.
# custom:
#   id: MISSION-001
#   clause: Mission profile (applies CCSDS 355.0-B-2 authentication service to TC)
#   severity: critical
deny contains f if {
	some vc in sdls.virtual_channels
	vc.carries == "telecommand"
	key := sdls.vc_key(vc)
	not authenticated(key)
	f := sdls.finding("MISSION-001", "mission profile, CCSDS 355.0-B-2 authentication service", vc, sprintf("telecommand channel %s has no SA providing authentication or authenticated encryption", [key]))
}

authenticated(key) if {
	some sa in sdls.security_associations
	key in sdls.sa_gvcid_keys(sa)
	sdls.provides_authentication(sa)
}

# METADATA
# title: MISSION-002 Keys are referenced, never embedded
# description: >-
#   The SA database is versioned and shared with integrators; key material
#   in it would leak with every copy. Keys live in a KMS/HSM and the SA
#   holds only a reference.
# custom:
#   id: MISSION-002
#   clause: Mission profile (key management hygiene)
#   severity: critical
deny contains f if {
	some sa in sdls.security_associations
	some field in {"key", "key_value", "key_hex", "secret"}
	field in object.keys(sa)
	f := sdls.finding("MISSION-002", "mission profile, key management", sa, sprintf("contains inline key material in '%s'; reference the key with key_ref instead", [field]))
}

deny contains f if {
	some sa in sdls.security_associations
	not valid_key_ref(object.get(sa, "key_ref", ""))
	f := sdls.finding("MISSION-002", "mission profile, key management", sa, sprintf(
		"key_ref must be a URI with one of the schemes %v, got '%v'",
		[sort(mission_profile.allowed_key_ref_schemes), object.get(sa, "key_ref", "")],
	))
}

valid_key_ref(ref) if {
	is_string(ref)
	parts := split(ref, "://")
	count(parts) == 2
	parts[0] in mission_profile.allowed_key_ref_schemes
	parts[1] != ""
}
