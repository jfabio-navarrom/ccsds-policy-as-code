# Design decisions

## 1. What artifact to check: the SA database

Almost all SDLS security is in *managed parameters*: values that both ends
of the link get before launch (CCSDS 355.0-B-2 §4.2.1.2 asks sender and
receiver to start from a common SA database). So the SA database is the one
place where a bad setting is cheap to find before launch and expensive to
miss: once the spacecraft flies, changing it needs SDLS Extended Procedures
or a software upload.

The input format ([input-format.md](input-format.md)) uses the same words as
the standard on purpose (SPI, GVCID, IV length, sequence number window), so a
reviewer can map any field back to Table 6-1 of 355.0-B-2 without a glossary.

## 2. Why OPA / Rego and Conftest

| Option | Why / why not |
|---|---|
| **OPA + Conftest** (chosen) | Works with any format (YAML, JSON, HCL, Terraform plans), so the same policies can run on IaC later. Policies work on data and have unit tests. Annotations keep the control mapping inside the code. |
| Checkov custom policies | Good for cloud IaC, but it does not know SA databases as a resource type; custom checks would be extra Python code. |
| HashiCorp Sentinel | Tied to Terraform Cloud / Enterprise. Not a good fit for a mission config file. |
| JSON Schema | Good for shape (types, ranges), but it can not express rules across objects like "only one SA per GVCID" or "every telecommand VC is covered by an authenticating SA". |

## 3. Standard vs. mission profile

CCSDS standards say *how* to protect a link, not *which* links a mission
must protect. Mixing both would give a wrong picture of the standard. So:

- `sdls.*` and `crypto.*` only contain what the Blue Books say, with the clause in
  every finding.
- `mission.*` contains risk decisions (authenticate every telecommand VC, never
  put keys in the file) and gives the reason. Values you can change are in one
  file, `policy/mission/profile.rego`.

## 4. deny vs. warn

| Standard language | Enforcement | Example |
|---|---|---|
| "shall" | `deny` | GCM tag shall be 128 bits (`CRYPTO-004`) |
| "shall … unless agreed a priori" | `deny` unless the agreement is recorded in the SA, then `warn` | HMAC truncation (`CRYPTO-006`) |
| "should" / "other modes … should be carefully considered" | `warn` | Non-CTR encryption mode (`CRYPTO-003`) |
| Mission hardening beyond the standard | `warn` | TC replay window above profile maximum (`SDLS-022`) |

Writing the agreement as a field (`truncation_agreed`,
`alternative_hash_agreed`) turns a decision made outside the file into
evidence that can be reviewed and is versioned.

## 5. Finding format

Every rule gives `{msg, policy_id, clause}`. Conftest prints `msg`; the JSON
output keeps `policy_id` and `clause` as metadata, so findings can go to a
ticket system or a GRC tool without parsing text.

## Lesson learned: fail closed

The first version of `SDLS-001` read:

```rego
not sa.service in sdls.valid_services
```

The idea: fail when the service is not one of the three allowed ones. The test
for a **missing** `service` field failed: the rule said nothing. In OPA, when
`sa.service` is undefined the expression is not read as "not in the set", so a
config that just leaves out the field got through. The algorithm checks had the
same problem: an SA with no `cipher` at all would have passed `CRYPTO-001`
("encryption uses AES").

For a security control this is the worst way to fail: the less information
the config gives, the more it passes. The fix is to read every field with a
default (`object.get(x, "field", null)`), so a missing field is compared as a
real value that does not match. Four regression tests
(`test_*_fails_closed_on_missing_*`) keep it fixed. I also added `SDLS-006`, so
an SA with no protocol can not bind to zero channels without a warning and pass
every channel rule for free.
