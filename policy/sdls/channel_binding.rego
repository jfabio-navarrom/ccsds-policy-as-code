# METADATA
# title: SDLS SA-to-channel binding
# description: >-
#   Rules about which Virtual Channels an SA may be attached to. Getting
#   this wrong means frames are sent unprotected, or protected with an
#   ambiguous SA that the receiver cannot resolve.
# custom:
#   standard: CCSDS 355.0-B-2 (Space Data Link Security Protocol)
package sdls.channel_binding

import data.lib.sdls
import rego.v1

# METADATA
# title: SDLS-010 One SA at a time per Global VC at the sending end
# custom:
#   id: SDLS-010
#   clause: CCSDS 355.0-B-2 §4.2.2.2.2
#   severity: high
deny contains f if {
	some i, a in sdls.security_associations
	some j, b in sdls.security_associations
	i < j
	shared := sdls.sa_gvcid_keys(a) & sdls.sa_gvcid_keys(b)
	count(shared) > 0
	f := sdls.finding("SDLS-010", "CCSDS 355.0-B-2 §4.2.2.2.2", b, sprintf(
		"shares channel(s) %v with SA spi=%v; only one SA may be used at a time on a Global VC",
		[sort(shared), a.spi],
	))
}

# METADATA
# title: SDLS-011 No SA on Virtual Channels that carry only idle data
# custom:
#   id: SDLS-011
#   clause: CCSDS 355.0-B-2 §4.2.2.2.3
#   severity: medium
deny contains f if {
	some sa in sdls.security_associations
	some key in sdls.sa_gvcid_keys(sa)
	sdls.vcs_by_key[key].carries == "idle_only"
	f := sdls.finding("SDLS-011", "CCSDS 355.0-B-2 §4.2.2.2.3", sa, sprintf("is bound to idle-only channel %s; SAs must not be created for VCs carrying only OID frames", [key]))
}

# METADATA
# title: SDLS-012 With COP in use, an SA covers exactly one VC
# custom:
#   id: SDLS-012
#   clause: CCSDS 355.0-B-2 §5.4 c)
#   severity: high
deny contains f if {
	some sa in sdls.security_associations
	keys := sdls.sa_gvcid_keys(sa)
	count(keys) > 1
	some key in keys
	sdls.vcs_by_key[key].cop == true
	f := sdls.finding("SDLS-012", "CCSDS 355.0-B-2 §5.4 c)", sa, sprintf("covers %d VCs but %s uses COP; an SA must be associated with one VC only when COPs are used", [count(keys), key]))
}

# METADATA
# title: SDLS-013 SA references a declared Virtual Channel
# description: >-
#   Consistency check, not a CCSDS clause: an SA pointing at a VC that the
#   mission never declared is almost always a typo that leaves the real VC
#   unprotected.
# custom:
#   id: SDLS-013
#   clause: Consistency check (supports CCSDS 355.0-B-2 §4.2.2.1)
#   severity: medium
deny contains f if {
	some sa in sdls.security_associations
	some key in sdls.sa_gvcid_keys(sa)
	not sdls.vcs_by_key[key]
	f := sdls.finding("SDLS-013", "consistency check, supports CCSDS 355.0-B-2 §4.2.2.1", sa, sprintf("references channel %s, which is not declared in virtual_channels", [key]))
}
