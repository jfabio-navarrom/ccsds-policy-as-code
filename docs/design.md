# Design decisions

## 1. What artifact to check: the SA database

SDLS security lives almost entirely in *managed parameters*: values that both
ends of the link are provisioned with before launch (CCSDS 355.0-B-2 §4.2.1.2
requires sender and receiver to initialise a common SA database). That makes
the SA database the single place where a misconfiguration is both cheap to
catch and expensive to miss: once the spacecraft flies, changing it means
SDLS Extended Procedures or a software upload.

The input format ([input-format.md](input-format.md)) is deliberately close to
the standard's vocabulary (SPI, GVCID, IV length, sequence number window) so
that a reviewer can map any field back to Table 6-1 of 355.0-B-2 without a glossary.

## 2. Why OPA / Rego and Conftest

| Option | Why / why not |
|---|---|
| **OPA + Conftest** (chosen) | Format-agnostic (YAML, JSON, HCL, Terraform plans), so the same policies can later run on IaC. Policies are data-driven and unit-testable. Annotations carry the control mapping inside the code. |
| Checkov custom policies | Strong for cloud IaC, but SA databases are not a resource type it knows; custom checks would be Python glue. |
| HashiCorp Sentinel | Tied to Terraform Cloud / Enterprise. Not a fit for a mission config file. |
| JSON Schema | Good for shape (types, ranges), cannot express cross-object rules like "only one SA per GVCID" or "every telecommand VC is covered by an authenticating SA". |

## 3. Standard vs. mission profile

CCSDS standards define *how* to protect a link, not *which* links a mission
must protect. Mixing the two would misrepresent the standard. So:

- `sdls.*` and `crypto.*` encode only what the Blue Books say, with the clause in
  every finding.
- `mission.*` encodes risk decisions (authenticate every telecommand VC, never
  embed keys) and states its rationale. Tunable values live in one file,
  `policy/mission/profile.rego`.

## 4. deny vs. warn

| Standard language | Enforcement | Example |
|---|---|---|
| "shall" | `deny` | GCM tag shall be 128 bits (`CRYPTO-004`) |
| "shall … unless agreed a priori" | `deny` unless the agreement is recorded in the SA, then `warn` | HMAC truncation (`CRYPTO-006`) |
| "should" / "other modes … should be carefully considered" | `warn` | Non-CTR encryption mode (`CRYPTO-003`) |
| Mission hardening beyond the standard | `warn` | TC replay window above profile maximum (`SDLS-022`) |

Recording an a-priori agreement as a field (`truncation_agreed`,
`alternative_hash_agreed`) turns an out-of-band decision into reviewable,
versioned evidence.

## 5. Finding format

Every rule emits `{msg, policy_id, clause}`. Conftest prints `msg`; the JSON
output keeps `policy_id` and `clause` as metadata, so findings can be routed to a
ticketing system or a GRC tool without parsing strings.

## Lesson learned: fail closed

The first version of `SDLS-001` read:

```rego
not sa.service in sdls.valid_services
```

The intent: fire when the service is not one of the three allowed. The test for a
**missing** `service` field failed: the rule stayed silent. In OPA, when
`sa.service` is undefined the expression is not evaluated as "not in the set",
so a config that simply omits the field slipped through. The same pattern
existed in the algorithm checks: an SA with no `cipher` at all would have passed
`CRYPTO-001` ("encryption uses AES").

For a security control this is the worst possible failure mode: the less
information the config gives, the more it passes. The fix is to read every
field through a default (`object.get(x, "field", null)`) so absence compares as
a concrete non-matching value. Four regression tests
(`test_*_fails_closed_on_missing_*`) keep it fixed, and `SDLS-006` was added so
an SA with no protocol cannot quietly bind to zero channels and pass every
channel-based rule vacuously.
