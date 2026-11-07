# METADATA
# title: SDLS helpers
# description: >-
#   Shared helpers to navigate an SDLS Security Association database
#   (see examples/ for the input format). No rules here produce findings.
package lib.sdls

import rego.v1

security_associations := object.get(input, "security_associations", [])

virtual_channels := object.get(input, "virtual_channels", [])

legacy := object.get(object.get(input, "metadata", {}), "legacy_implementation", false)

authentication_services := {"authentication", "authenticated_encryption"}

encryption_services := {"encryption", "authenticated_encryption"}

valid_services := authentication_services | encryption_services

supported_protocols := {"TC", "TM", "AOS", "USLP"}

provides_authentication(sa) if sa.service in authentication_services

provides_encryption(sa) if sa.service in encryption_services

# A Global VC ID is only unique within a protocol (a TC VC 0 and a TM VC 0
# share TFVN/SCID/VCID but live on different physical channels).
gvcid_key(protocol, g) := sprintf("%s:%v/%v/%v", [protocol, g.tfvn, g.scid, g.vcid])

sa_gvcid_keys(sa) := {gvcid_key(sa.protocol, g) | some g in object.get(sa, "gvcids", [])}

vc_key(vc) := gvcid_key(vc.protocol, vc.gvcid)

vcs_by_key := {vc_key(vc): vc | some vc in virtual_channels}

sa_label(sa) := sprintf("SA spi=%v (%s)", [
	object.get(sa, "spi", "?"),
	object.get(sa, "description", "no description"),
])

# Standard finding shape. Conftest prints `msg`; the rest is kept in JSON
# output so a pipeline can route findings by control and severity.
finding(id, clause, sa_or_vc, text) := {
	"msg": sprintf("[%s] %s: %s (%s)", [id, label(sa_or_vc), text, clause]),
	"policy_id": id,
	"clause": clause,
}

label(x) := sa_label(x) if "spi" in object.keys(x)

label(x) := sprintf("VC %s", [x.name]) if not "spi" in object.keys(x)
