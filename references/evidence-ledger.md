# Evidence ledger schema

Use `--ledger PATH` to write a `hermes-evidence-ledger/v1` JSON artifact for a
completed research run. It is an audit aid, not a factual truth score.

## Finding states

- `independently-corroborated`: at least two distinct conservative
  publisher/service origins support the merged finding.
- `structured-record`: one origin is an official or structured registry/API
  record. This describes provenance, not correctness.
- `rediscovered-single-origin`: multiple adapters found the same origin. This is
  useful retrieval redundancy, but not independent corroboration.
- `single-origin`: one other publisher/service origin supports the finding.

Origins are reduced to publisher/service domains. Common API and search
subdomains are collapsed, as are a small set of common multipart public suffixes.
This deliberately underclaims independence when identity is ambiguous.

## Top-level fields

- `schema`: currently `hermes-evidence-ledger/v1`.
- `query`, `generated_at`, `routing`: run provenance.
- `summary`: counts by finding state and the independence method.
- `findings`: merged on-topic findings and all retained support records.
- `limitations`: machine-readable cautions that must travel with the artifact.

Each finding contains a stable `id`, finding text, lane, status, origin and
adapter counts, roles, support records, and contradiction fields. Contradictions
remain `not-assessed-without-full-text`; do not infer agreement from their empty
list. A future full-text verification stage may populate them while preserving
the v1 provenance fields.
