# METADATA
# title: Mission security profile
# description: >-
#   Tunable values a mission sets for itself on top of the CCSDS baseline.
#   CCSDS defines the mechanisms; the mission decides how strict to be.
#   Override by shipping a different version of this package.
package mission_profile

import rego.v1

# Largest anti-replay window accepted on a telecommand SA (SDLS-022).
max_tc_window := 16

# Key references must point at a key store, never at inline material (MISSION-002).
allowed_key_ref_schemes := {"kms", "hsm", "pkcs11"}
