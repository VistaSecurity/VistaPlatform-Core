# The learned matcher

The model behind ADR-0002 D3's third outcome: when the identifiers disagree and
a merge proposal is opened, this is what ranks the candidates, says why, and —
above a threshold the tenant sets deliberately — lets a rule accept the top one.

Workstream 4.6. ADR-0008 D1 (the seam), D2 (classical, in-process, Core), D4
(honesty), D5 (a rule or a human approves; a model proposes).

---

## What it is

A logistic regression over twenty pairwise features, trained offline, shipped as
`weights.json` embedded in the binary, evaluated in pure Go. No runtime, no
network, no ONNX, no dependency outside the standard library and
`shared/assetclass`.

Three properties are the reason it is a logistic regression rather than
something with more capacity:

1. **It is explainable by construction.** The score is `sigmoid(Σ wᵢxᵢ)`, so
   `Model.Explain` is not an approximation of what the model did — it *is* what
   the model did, and `TestExplainIsTheScore` asserts the factors sum to the
   log-odds exactly. Nothing post-hoc is guessing at the model's reasoning.
2. **It is calibrated.** Fitted by minimising log-loss, so the output reads as a
   probability: 0.5 is "as likely as not", and a tenant setting a threshold of
   0.9 is asking for something meaningful rather than choosing a number on an
   arbitrary scale.
3. **It is auditable.** Twenty weights in a committed JSON file, reproducible
   from committed fixtures by a committed command.

## Where the pieces are

| | |
|---|---|
| `features.go` | The allowlist: `Pair` → `Vector`. Nothing reaches the model except through here. |
| `similarity.go` | Token Jaccard and Jaro-Winkler, hand-written. |
| `model.go` | The scorer, `Explain`, the singleton ceiling, the embedded weights. |
| `train.go` | `Sample`, `Train`, `Evaluate`, `Metrics`. |
| `testdata/fixtures.json` | The labelled set. |
| `weights.json` | The shipped model. Generated; see below. |
| `cmd/train-matcher` | The trainer. |
| `../../ai/seams/learned_matcher.go` | The seam adapter, and the registry default. |

The adapter lives in `shared/ai/seams` rather than here because `shared/identity`
imports the seam types, so a matcher package importing them while `seams`
registered it as a default would close an import cycle. The consequence is
deliberate: this package is pure arithmetic over a `Pair` and knows nothing about
seams, which is what makes it testable and shippable on its own.

For the same reason the identifier-kind vocabulary is restated here as strings
rather than imported from `shared/identity`. `TestMatcherKindVocabularyMatchesIdentity`
(in `shared/identity`, which *may* import this package) fails if the two drift.

## The features

Every one is a **comparison**, not a value carried over from either side. That
is what makes "the model never sees key material or raw metadata" structural
rather than a promise: there is no path from a `Pair` into the model except
`Features()`, and its return value is twenty numbers.

| Feature | 1 when… |
|---|---|
| `bias` | always (the intercept — the base rate on the conflict path, which is low) |
| `id_match_singleton` | a one-per-asset kind agrees: `agent_id`, `cloud_resource_id`, `serial_number`, `cmdb_sys_id` |
| `id_conflict_singleton` | both sides carry the same singleton KIND with different values |
| `id_match_strong` | a tenant-unique non-singleton kind agrees: `ssh_host_key_fingerprint`, `mac_address`, `fqdn` |
| `id_match_weak` | a scope-local kind agrees: `hostname`, `ip_address`, `name` |
| `id_match_breadth` | graded: `min(kinds agreeing, 4) / 4` |
| `name_similarity` | graded: the best of token Jaccard and Jaro-Winkler across both sides' names and name-like identifiers |
| `name_sequential` | the names differ ONLY in a trailing number (`web01` / `web02`) |
| `vendor_match` / `vendor_conflict` | both vendors known and equal / both known and different |
| `model_match` / `model_conflict` | the same, for the hardware model |
| `class_equal` / `class_related` / `class_conflict` | same class / one an ancestor of the other / both known and unrelated |
| `segment_match` / `segment_conflict` | same network segment / two different known ones |
| `recency` | graded: `exp(-days / 30)` between the two sightings, 0 when either time is unknown |
| `source_same` / `source_cross` | the two sides' ADR-0005 source kinds are equal / differ |

Three conventions run through the list and each exists because getting it wrong
is a bug this codebase has already had:

- **Unknown is neither.** An absent vendor sets neither `vendor_match` nor
  `vendor_conflict`. "Not assessed stays not assessed" (ADR-0008 D4.3) at the
  feature level — an absence must not read as agreement.
- **Only SINGLETON disagreement is evidence.** A machine legitimately has several
  MACs, addresses and names, so two differing MACs say nothing. Two differing
  ARNs say everything.
- **A differing singleton is not a score.** `Model.Score` caps at
  `SingletonConflictCeiling` (0.05) when `id_conflict_singleton` is set, and the
  engine refuses an auto-accept on one *without consulting any score at all*.
  Two independent mechanisms; the engine's is the load-bearing one. The ceiling
  is not zero because zero means UNSCORED everywhere else in this codebase, and
  a confident rejection is not an absence of opinion.

### Things the model learned that are worth knowing

`vendor_match` came out **negative** (−0.38). That is not a bug: a rack of
identical switches agrees on vendor and model and is emphatically not one
switch, so "same vendor" alone is weak-to-negative evidence. What makes that
reading coherent rather than a fixture artefact is that `vendor_conflict` is
lower still (−1.04), and `TestAgreeingIsNeverWorseEvidenceThanDisagreeing`
pins the ordering for every such pair. `source_same` is
also negative (−0.92) while `source_cross` is positive (+0.72) — two independent
sources corroborating is the textbook positive, and one collector emitting two
rows for one thing is the textbook duplicate.

## The fixtures

`testdata/fixtures.json` — 73 labelled pairs, 35 matches and 38 non-matches.
Deliberately not a sample of anything: it is a set of **named failure modes**,
one row per shape, written so that a model which cannot separate them fails
visibly.

The positives are "the same host seen by two sources": a serial matching across
a rename, a cloud ARN matching a sensor sighting, an SSH host key surviving a
rebuild, a CMDB row meeting a measured host, an FQDN meeting a short hostname.

The negatives are the classic traps:

| Trap | Why it looks like a match |
|---|---|
| Same address, different serial | the address is the strongest thing they share and it is reassigned |
| Same address, different cloud id | two VPCs with the same CIDR (ADR-0002 D3's second erratum) |
| Same hostname, different segment | every segment has a `db01` |
| Identical vendor and model, nothing else | a rack of the same switch |
| Sequential names | `web01` / `web02` — maximally similar by every string measure |
| Two VMs from one template | same name, different `agent_id` |
| Same name, different class | a service called `payments` and a server called `payments` |
| A reused DHCP lease months apart | same address, different everything, far apart in time |

`TestEveryFeatureIsExercisedByTheFixtures` fails if a feature is never set by any
fixture: a weight fitted on no evidence is a number the data never expressed.

## Training

```bash
cd shared/identity/matcher

# Reproduce the shipped weights from the shipped fixtures.
go run ./cmd/train-matcher -out weights.json

# Measure the shipped weights without changing them.
go run ./cmd/train-matcher -eval-only

# Retrain including a tenant's real merge decisions.
go run ./cmd/train-matcher -decisions exported.json -out weights.json
```

Training is **deterministic**: weights start at zero, the batch is the whole set
in file order, and there is no shuffling or random initialisation. Two runs
produce byte-identical output, which is what lets
`TestEmbeddedWeightsAreReproducibleFromTheFixtures` assert that `weights.json`
is the file the committed fixtures produce. A weights file nobody can reproduce
is a number with no provenance, and a hand-edited one would ship
indistinguishably from a real one.

Hyper-parameters are constants (`DefaultIterations`, `DefaultLearningRate`,
`DefaultL2`) rather than tuned per run, because the weights file records the
accuracy it achieved and a retrain that quietly used different ones would make
that number incomparable. The ridge penalty is not applied to the bias —
penalising the intercept would pull the base rate towards 0.5 regardless of the
data, which is a claim about the world rather than a regularisation.

### Measured

At the time of writing, on the committed fixtures:

```
accuracy 1.0000  precision 1.0000  recall 1.0000  log-loss 0.1074

                 predicted match   predicted separate
  actual match                 35                    0
  actual separate               0                   38
```

Five-fold held-out: **0.9863 (72/73)**, the single miss being
`negative/sequential-names-cross-source`.

In-sample 1.0 is not evidence of quality and must not be read as any — the
fixtures are *designed* to be separable, so it says the feature set can express
the traps and nothing more. `TestHeldOutFoldsGeneralise` is the number that
means something, and the 0.90 floor is asserted on **both**.

### Training on real decisions

`-decisions` takes a JSON file in the same shape as the fixtures. Real decisions
are **appended** to the fixtures and weighted identically — dropping the
fixtures would let one tenant's population teach the model that a trap it has
never encountered does not exist.

The label comes from the proposal's own outcome: a proposal a reviewer resolved
`merged` is `"match": true`, one resolved `kept_separate` is `"match": false`. A
proposal still `pending` is **not a label** and must not be exported as one — an
unanswered question is not an answer, and feeding it in as a negative teaches the
model to agree with whatever the queue has not got to yet.

Exporting is an operator step, run against the tenant's database with the tenant
session set. The proposal rows are `asset_history` entries; the sketch:

```sql
SET LOCAL app.tenant_id = '<tenant-uuid>';

SELECT h.id,
       h.changes_json ->> 'status'               AS outcome,       -- merged | kept_separate
       h.changes_json ->> 'observation_asset_id' AS observation_id,
       c ->> 'asset_id'                          AS candidate_id
  FROM asset_history h
  CROSS JOIN LATERAL jsonb_array_elements(h.changes_json -> 'candidates') AS c
 WHERE h.action = 'merge_proposed'
   AND h.changes_json ->> 'kind' = 'merge_proposal'
   AND h.changes_json ->> 'status' IN ('merged', 'kept_separate');
```

Each row gives you a pair of asset ids; the two `Side`s are then built from
`assets` (display name, class, segment, last-seen, `attributes->>'vendor'` and
`attributes->>'model'`) and `asset_identifiers` (kind → value), which is exactly
what `identity.Repository.LoadSummaries` reads. Note what the history row does
**not** carry: the observation's own identifiers as they were at the time. For a
proposal that created an observation asset they are that asset's; for the floor
case they are only on the proposal's `matched_identifiers`, which is a subset.
An export is therefore a reconstruction, and a lossy one — which is another
reason the synthetic fixtures stay in the set.

**Never export identifier VALUES you do not need.** The samples are a training
file that will sit on somebody's disk; they carry serials and hostnames because
the extractor compares them, and they must not leave the tenant's control.

## Retraining checklist

1. Change the fixtures, or supply `-decisions`.
2. `go run ./cmd/train-matcher -out weights.json`.
3. Read the confusion matrix and the misclassified list the tool prints. A new
   miss names a case, not a percentage.
4. `go test ./...` here. Three tests are the gate:
   - `TestEmbeddedWeightsAreReproducibleFromTheFixtures` — the file is the one
     the fixtures produce;
   - `TestHeldOutFoldsGeneralise` — ≥ 0.90 on data the model has not seen;
   - `TestTrainedWeightSigns` — for the identifier features, evidence of
     sameness does not subtract and evidence of difference does not add. The
     monotonicity property (`TestAddingAMatchingIdentifierNeverLowersTheScore`)
     rests on those signs, and a retrain that flipped one would leave the model
     still accurate and quietly untrue to it.
   - `TestAgreeingIsNeverWorseEvidenceThanDisagreeing` — the paired attribute
     features do not contradict each other. It is an ORDERING, not a sign,
     precisely because `vendor_match` is legitimately negative: the statement
     that has to hold is `vendor_conflict ≤ vendor_match`, and the same for
     model, class and segment. A retrain producing "different vendors is better
     evidence of sameness than the same vendor" keeps its accuracy, keeps its
     held-out score and satisfies the sign test, because neither feature is in
     either of its lists.
5. Bump `model_id` if the change is one anybody should be able to tell apart in
   an audit. The id is written onto every proposal the model scores.
6. `cd ../.. && go test ./identity/...` — the vocabulary guard and the engine's
   integration with the seam.

## What it may never do

- **Decide.** ADR-0008 D5. The rule-based precedence walk of ADR-0002 D3 decides
  identity; this is consulted only on the conflict path, and only to rank.
- **Override a singleton disagreement.** Both the ceiling here and the engine's
  guard.
- **Read an asset's approval status.** `seams.AssetSummary.Status` exists for the
  engine's auto-accept guard, and `Side.Status` carries it, but no feature reads
  it: where an asset sits in the approval queue says nothing about whether it is
  the same physical thing, and a model that learned to favour approved assets
  would be laundering an approval decision into an identity one.
- **See anything outside `Features()`.** Add a feature and you widen what the
  model can see; that is a decision to take deliberately, in a review, not by
  adding a map key.
