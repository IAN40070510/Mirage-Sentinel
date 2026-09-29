# Commerce HTTP dataset: review-v1

This batch is a 15-record, offline-only format review set. It was not sent to a
local, OCI, or third-party endpoint. It is not a training, validation, or test
split, and it has no model scores.

## Provenance

- Batch ID: `commerce-review-v1`
- Generated at: `2026-09-22T18:38:06.990+08:00`
- Generation method: offline request construction from repository source review
- Generation model: OpenAI Codex, GPT-5 family; exact deployment identifier was
  not exposed to the artifact-generation context
- Prompt version: `docs/DATASET_GENERATION_PROMPT.md`, SHA-256
  `b2ffc74ea021bae12c090fd82f1d0dbfdd27ff75a98af513f834f826243ea680`
- Random seed: not applicable; no random sampler was used
- Repository commit at generation:
  `fcbea45a62eae597a9a214c81b1efbdf9d4b1540`
- Dataset SHA-256:
  `4059ce9c4b0bfe95f22dbd82b5dd2732de3ed9a510374eaa257dc15c367ddf5b`
- Schema SHA-256:
  `e6fd1cd3c3607676975b41f7a5f0aa5990455741fa00363c208259874c4c65aa`
- Normalization/redaction version: `commerce-redaction-v1`
- Counts before/after exact deduplication: 15 / 15

The working tree already contained uncommitted changes when this batch was
created. In particular, `services/commerce/detection.py` and
`model/commerce/features.json` were not modified by this work.

## Repository/API basis

The request shapes were derived from the current repository copies of:

- `services/commerce/detection.py`
- `model/commerce/features.json`
- `scripts/smoke_commerce.py`
- `commerce/apps/backend/src/api/`
- `commerce/apps/storefront/src/lib/data/`

The reviewed flows include region and product reads, customer registration and
login, cart creation, line-item creation, addresses, shipping options, payment
sessions, cart completion, and order reads. The custom backend source only adds
the file-based `/store/custom` and `/admin/custom` routes; standard Medusa store
routes are supplied by the framework and are exercised by the smoke and
storefront code.

No API was queried for IDs during this offline batch. Values prefixed with
`reg_PLACEHOLDER`, `cart_PLACEHOLDER`, or `variant_PLACEHOLDER` are explicitly
unverified. They must be replaced with IDs first read from an authorized,
isolated local test deployment before any later execution. Nothing in this batch
claims a completed cart, payment, order, vulnerability, or successful exploit.

## Class statistics

| Field | Value | Count |
| --- | --- | ---: |
| label | normal | 7 |
| label | sqli | 2 |
| label | xss | 2 |
| label | cmdi | 2 |
| label | path_traversal | 2 |
| review_status | generated_unverified | 15 |
| review_status | reviewed | 0 |

Normal records include four browser-shaped requests and three API-client-shaped
requests. Attack records include four browser-shaped requests and four
API-client-shaped requests, one of each client shape per attack class. User-Agent
values overlap normal and attack labels and are not intended as class signals.

The normal examples cover region browsing, product listing, a legitimate search
with special characters, a search with no expected result, account registration,
cart creation, and adding a line item. Account and cart records are formats only;
they do not represent executed sessions.

## Data dictionary

| Field | Type | Required | Meaning and constraints |
| --- | --- | --- | --- |
| `sample_id` | string | yes | Unique stable record identifier for traceability and per-record predictions. |
| `template_family` | string or null | no | Groups variants produced from the same template so future splits keep them together. |
| `request.method` | uppercase string | yes | HTTP method visible at routing time. |
| `request.path` | string | yes | Leading-slash request path as intended for transmission. It excludes the query string. |
| `request.query` | string | yes | Raw encoded query without a leading `?`; an empty query is `""`. It must not be silently decoded or reordered. |
| `request.headers` | object of strings | yes | Headers available at routing time. Reusable Cookie/Authorization values are prohibited. |
| `request.body` | string or null | yes | Exact pending body string, or null. Form data remains form data; JSON text remains a string. |
| `label` | enum | yes | Training target `y`: `normal`, `sqli`, `xss`, `cmdi`, or `path_traversal`. |

The JSONL contract contains only `sample_id`, optional `template_family`,
`request`, and `label`. IDs, template families, and labels are excluded from `X`. Only request data available
at routing time and reproducible pre-request history may become features. The
training loader must select fields explicitly; it must never concatenate the
whole JSONL object.

## Labeling rules

- `normal`: ordinary browsing, search, membership, cart, and checkout behavior,
  including legitimate retries, spelling mistakes, no results, stock failure,
  or abandoned checkout. A quote, URL, command word, semicolon, or code fragment
  alone is insufficient for an attack label.
- `sqli`: the input has contextual intent to change SQL query semantics, such as
  terminating a value and adding a boolean predicate. SQL vocabulary alone is
  insufficient.
- `xss`: the input attempts to become executable browser content. Plain HTML or
  code discussion is not automatically XSS.
- `cmdi`: the input attempts to introduce server shell-command execution. A
  command name or separator without that contextual intent is insufficient.
- `path_traversal`: the input attempts to cross an allowed directory boundary.
  Generic local-file access or an arbitrary file name is not automatically path
  traversal.

Attack labels mean attempted input only. They do not assert that Medusa or the
gateway is vulnerable or that the attempt succeeded. Ambiguous, mixed-class,
SSTI, and SSRF records were excluded rather than forced into a class. The
pending-review list for such excluded candidates is empty for this batch because
none were retained as dataset rows; all 15 retained rows still require review.

## Redaction and execution records

`commerce-redaction-v1` replaces any reusable publishable key or test password
with a bracketed placeholder, retains the raw encoded query, and performs no URL
decoding, case folding, body conversion, or path normalization. This batch has
no Cookie or Authorization values and no personal data; `example.invalid` is a
reserved synthetic domain.

A later executed batch must store a separate execution JSONL keyed by
`sample_id`. Each record must contain a timestamp with milliseconds or
microseconds, the actual transmitted request (including the client-observed raw
path), `response_status`, `route`, `response_origin`, and `latency_ms`. Response
content, routing decisions, and model predictions are observations, not ground
truth and not pre-request features. For traversal cases, capture the actual path
on the wire because clients and proxies may normalize it.

Any later collection must target only an explicitly authorized isolated local
deployment. It must first read real region, product, variant, cart, and shipping
option IDs from that deployment. Public OCI and third-party targets are out of
scope.

## Validation result

Run from the repository root:

```text
python scripts/validate_commerce_dataset.py
```

Result for the hashes above:

| Check | Result |
| --- | --- |
| UTF-8 decode, no BOM, newline-terminated JSONL | pass |
| One JSON object per non-empty line | pass |
| Required/allowed fields and enum values | pass |
| Records | 15 |
| Class counts | normal 7; sqli 2; xss 2; cmdi 2; path_traversal 2 |
| Duplicate `sample_id` values | 0 |
| Exact duplicate canonical requests | 0 |

The duplicate check canonicalizes only the five `request` fields as sorted JSON
and compares SHA-256 fingerprints. It is an exact request check, not a substitute
for the required near-duplicate grouping before a future split. Shared
`template_family` values deliberately identify related variants.

## Future expansion and leakage controls

Do not split this review batch. Once enough reviewed data exists, target 70/15/15
but form connected groups from non-empty `template_family` values and detected
near-duplicate relationships. Merge overlapping groups. Null families are not
one group. Keep complete operation files together when available; without
operation provenance, do not claim session-independent evaluation. Fit TF-IDF
and other learned transforms on training data only. Select thresholds using
validation data; the test split must not participate in tuning.

Future reports must include five-class and normal-versus-attack confusion
matrices; per-class precision, recall, F1, and support; macro-F1; normal false
positive rate; attack miss rate; and per-record predictions.
They must compare rules, model, and rules-plus-model. Mark unavailable metrics as
unavailable rather than inventing values.

## Current contract gap (not implemented here)

The current commerce detector is still binary. `model/commerce/features.json`
declares `binary:logistic`, `services/commerce/detection.py` enforces that
objective and exactly 12 features, and its public result centers on an `attack`
boolean plus one probability. No trained commerce `xgb.json` is present in this
worktree. This five-label JSONL therefore does not make inference multiclass.

Before future five-class deployment, an explicit versioned change must:

1. implement a training loader that extracts only approved request/history
   features and the `label` target;
2. perform grouped, near-duplicate-aware splitting before fitting transforms;
3. train a multiclass objective and package the model, vocabulary/IDF or other
   transforms, ordered features, class-to-index mapping, thresholds, and version
   together without pickle;
4. revise the detector compatibility check and response contract to expose
   per-class probabilities and a selected class while defining how the derived
   normal/attack decision remains backward compatible;
5. map or version the existing rule names (`command`, `traversal`) against the
   dataset labels (`cmdi`, `path_traversal`) and evaluate rule-only,
   model-only, and combined decisions separately; and
6. verify that inference loads only its portable deployment bundle, uses
   `pathlib`, CLI arguments, or environment variables, and works on both Windows
   and Linux ARM64 without the raw dataset or training directory.

None of those training or inference changes, and no deployment or Git push, was
performed for this review batch.

Schema update: removed source, session and annotation fields from all 15 records. Request content, labels, sample IDs and template families are unchanged. This format cleanup does not constitute label review.
