# Sources and verification status

| Standard | Edition used | How the clauses were checked |
|---|---|---|
| CCSDS 352.0-B-2, *CCSDS Cryptographic Algorithms* (Blue Book) | Issue 2 | Read from the public PDF at public.ccsds.org. All `CRYPTO-*` clause numbers come from this document. |
| CCSDS 355.0-B-2, *Space Data Link Security Protocol* (Blue Book) | Issue 2 | Clause numbers taken from the public review draft **355.0-P-1.1** (Pink Sheets, June 2021) that became Issue 2. **To do:** re-verify each `SDLS-*` clause against the published 355.0-B-2 PDF; renumbering between draft and issue is possible. |
| CCSDS 350.1-G, *Security Threats against Space Missions* (Green Book) | — | Informational. Cited only as rationale for `MISSION-*` rules, never as a requirement. |
| CCSDS 355.1-B-1, *SDLS Extended Procedures* | — | Not yet implemented (roadmap: key and SA lifecycle states). |

## Requirement → field interpretation

Where a clause needed interpretation to become a check, the choice is written here so a reviewer can challenge it.

| Policy | Clause text (abridged) | Interpretation |
|---|---|---|
| SDLS-003 | Table 6-1: SPI range 1..65534 | SPI 0 and 65535 are rejected. |
| SDLS-004 | §4.2.2.3: frames with the same SPI on a Master Channel share a single SA | Two SA entries with the same SPI on the same protocol are a conflict. |
| SDLS-010 | §4.2.2.2.2: at the sending end only one SA at a time per Global VC / MAP | The database is the sending-end view; overlapping GVCIDs between SAs are rejected. Rekeying by swapping SAs is modelled as two database versions, not two concurrent entries. |
| SDLS-020/021 | §4.2.2.6.1: every authenticating SA specifies an anti-replay sequence number and window | Sequence number length must be in the Table 6-1 range (2..8 octets) and the window > 0. |
| SDLS-031 | §4.1.2.2: Security Trailer present when authentication or authenticated encryption is applied | MAC length 8..64 octets for authenticating SAs, and 0 for encryption-only SAs. |
| SDLS-032 | §4.1.1.1.4: Security Header ≤ 64 octets | Header = SPI (2) + IV + sequence number + pad length fields. |
| CRYPTO-002 | §3.2.1: missions planned after Issue 2 shall use 256-bit keys; §3.2.2: existing ones may use 128 | `metadata.legacy_implementation: true` claims the allowance and produces a warning. |
| CRYPTO-005 | §4.2.2.2: HMAC shall normally use SHA-256; §4.2.2.3.1: alternatives agreed a priori | SHA-384/512 need `alternative_hash_agreed: true`. SHA-1 is always rejected (§4.2.2.3.2). |
