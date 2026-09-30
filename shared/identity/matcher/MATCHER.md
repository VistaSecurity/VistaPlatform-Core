# The learned matcher

The model behind ADR-0002 D3's third outcome: when the identifiers disagree and
a merge proposal is opened, this is what ranks the candidates, says why, and —
above a threshold the tenant sets deliberately — lets a rule accept the top one.

Workstream 4.6. ADR-0008 D1 (the seam), D2 (classical, in-process, Core), D4
(honesty), D5 (a rule or a human approves; a model proposes).

---

## What it is

A logistic regression over twenty-six pairwise features (v2, `matcher-logreg-v2`,
#2081 Phase 5), trained offline, shipped as `weights.json` embedded in the
binary, evaluated in pure Go. No runtime, no network, no ONNX. Its only
dependencies outside the standard library are pure-Go lookups the rest of the
identity stack already uses: `shared/assetclass` (class ancestry),
`shared/hostobs` (the IEEE OUI table) and `shared/identity/hostnamequality`
(generic and synthetic names).

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
3. **It is auditable.** Twenty-six weights in a committed JSON file,
   reproducible from committed fixtures by a committed command.

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
| `../../../scripts/export-merge-decisions.sql` | A tenant's resolved proposals as a `-decisions` file (lossless — see below). |
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
`Features()`, and its return value is `FeatureCount()` numbers.

**Several values per kind (v2).** `Side.Identifiers` is `kind → []value`,
because that is what an asset has: two NICs, a dual-stacked address pair, a
short name and an mDNS name. A kind counts as matched when ANY value agrees,
and a singleton conflicts only when NO value does. v1 carried one value per
kind and the engine kept whichever it met last, so a candidate whose SECOND
MAC was the observation's scored as though the MACs disagreed. A `Side` also
says which of its values were DERIVED (`Derived`, #2081 Phase 2) and which
names the intake judged GENERIC (`GenericNames`, #2081 B2 — including the
tenant-frequency signal only the engine can see). Samples accept a bare string
as a one-value list, so a v1 fixtures or decisions file still parses.

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
| `vendor_oui_match` / `vendor_oui_conflict` | the manufacturers behind each side's MACs (`hostobs.VendorForMAC`; falling back to the `vendor` attribute when no MAC has a registered prefix), compared by first word, share one / are both known and share none |
| `name_generic` | every best-matching name pair involves a GENERIC name (`hostnamequality.IsGeneric`, or one the intake marked) |
| `name_synthetic` | every best-matching name pair involves a SYNTHETIC name (`hostnamequality.IsIdentityName` false: UUID-form, an address written as a name, `none-N`) |
| `id_match_derived` | a kind agreed ONLY through a value one side derived rather than observed |
| `binding_conflict` | the two sides share an `ip_address` but not a MAC — both carry MACs, none in common |

### The v2 features and their expected signs

Each sign is stated where the feature is defined (`features.go`) and held by a
test, because a retrain that flipped one would keep its accuracy and quietly
stop meaning what its label says:

| Feature | Expected | Why | Held by |
|---|---|---|---|
| `name_generic` | ≤ 0 | the similarity rests on a factory default (`iphone`) — every unrenamed phone announces it | `TestTrainedWeightSigns` |
| `name_synthetic` | ≤ 0 | two records called `198-51-100-23.local` share a lease; two random UUID names still look ~0.9 alike to Jaro-Winkler | `TestTrainedWeightSigns` |
| `id_match_derived` | ≤ 0, **and** `id_match_strong + id_match_derived ≥ 0` | a derivation is an inference, never better than seeing the value — but a derived MAC still VOTES (owner decision D3), so the discount may not turn it into evidence of two things | `TestTrainedWeightSigns`, `TestADerivedMatchIsStillEvidenceForTheMatch` |
| `binding_conflict` | ≤ 0 | the address passed to another NIC: the lease-reuse shape the engine's address-only link rule (C1) refuses | `TestTrainedWeightSigns`, `TestBindingConflictDiscountsTheSharedAddress` |
| `vendor_oui_match` / `_conflict` | no sign; conflict ≤ match | exactly `vendor_match`'s story — a rack of identical hardware shares a NIC vendor — and weaker, because a laptop with a dock has two NIC vendors | `TestAgreeingIsNeverWorseEvidenceThanDisagreeing` |

Two further rules: a generic hostname, and a synthetic hostname or FQDN, never
counts as an IDENTIFIER agreement (it is recorded, but — as in the engine —
never votes); and the name properties hold only when they hold for EVERY pair
reaching the best similarity, which keeps them symmetric (`TestSymmetry`) and
means one ordinary, chosen name equally as good as the default clears the flag.

`binding_conflict` is the one feature by which an AGREEING value can lower a
score: an address shared across two different NICs is evidence of two things.
`TestAddingAMatchingIdentifierNeverLowersTheScore` exempts exactly that case —
an `ip_address` added where the feature then turns on — and nothing else. The
candidate is a whole asset, not an interface: the model cannot see which of
its MACs held the address, so a second NIC nobody has recorded produces the
same shape. That is why this is a learned weight and not a rule.

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

`vendor_match` came out **negative** (v2: −0.07; v1: −0.38), and
`vendor_oui_match` too (−0.28). That is not a bug: a rack of identical switches
agrees on vendor and model and is emphatically not one switch, so "same vendor"
alone is weak-to-negative evidence. What makes that reading coherent rather
than a fixture artefact is that the conflicts are lower still
(`vendor_conflict` −0.58, `vendor_oui_conflict` −0.66), and
`TestAgreeingIsNeverWorseEvidenceThanDisagreeing` pins the ordering for every
such pair. The two vendor features share most of their evidence (the OUI one
falls back to the attribute), so the ridge penalty splits the weight between
them; read them together. `source_same` is also negative (−0.89) while
`source_cross` is positive (+0.65) — two independent sources corroborating is
the textbook positive, and one collector emitting two rows for one thing is the
textbook duplicate.

`name_similarity` is small (+0.08; v1 +0.27): the fixtures are built around the
traps where names agree and nothing else does (sequential names, templates,
generic and generated names), and v2's `name_generic` / `name_synthetic` now
take the blame for part of what v1 put on the similarity itself.
`binding_conflict` is the largest v2 weight (−1.46), roughly cancelling the weak
address match it rides on.

## The fixtures

`testdata/fixtures.json` — 94 labelled pairs, 44 matches and 50 non-matches
(v1: 73 — 35 and 38). Every one is invented; the v2 rows are named `…/v2-…`.
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
| The lease passed to another NIC (v2) | same address, each side's MAC known and different |
| Two phones both called `iphone` (v2) | identical names, and the name is a factory default |
| Rotating or address-shaped names (v2) | `<uuid>.local` pairs look ~0.9 alike; `198-51-100-23.local` is the lease written as a name |
| A cloned VM kept its template's static IPv6 (v2) | the MAC derived from the EUI-64-shaped address is the TEMPLATE's |
| Sequential names from a CMDB and a sensor (v2) | the v1 held-out miss, now with a second instance |

The v2 positives are the shapes that must NOT be punished: a candidate's second
MAC matching, a dock NIC of another vendor on a laptop whose agent id agrees, a
replaced NIC under an unchanged FQDN and address, a generic or synthetic name
beside an agreeing MAC, and a derived MAC meeting the observed one.

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

At the time of writing, on the committed fixtures (`matcher-logreg-v2`):

```
accuracy 1.0000  precision 1.0000  recall 1.0000  log-loss 0.1220

                 predicted match   predicted separate
  actual match                 44                    0
  actual separate               0                   50
```

Five-fold held-out: **0.9468 (89/94)**. Four of the five misses fall in fold 3,
which by the index stride holds BOTH sequential-name cross-source negatives —
so its training folds contain neither and the trap is unlearnable there — plus
a lease-passed negative and an EUI-64 positive; the fifth is the cloned-VM
derived negative. Mean score: matches 0.88, non-matches 0.10.

v1 for comparison (`matcher-logreg-v1`, 73 fixtures): accuracy 1.0, log-loss
0.1074, held-out 0.9863 (72/73). The held-out number fell because v2 added
harder cases, not because it separates the old ones worse: every v1 fixture is
still on the right side of 0.5.

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

Export one with `scripts/export-merge-decisions.sql`, run as an operator:

```bash
psql "$DATABASE_URL" -X -q -At -v tenant_id=<tenant-uuid> \
     -f scripts/export-merge-decisions.sql > decisions.json
go run ./cmd/train-matcher -decisions decisions.json -out weights.json
```

**The export is lossless** (#2081 Phase 5). Every proposal row opened since v2
carries the matcher's whole view of both sides at the moment it was asked:
`observation_identifiers` (every identifier of the sighting, normalised, each
marked `derived` / `generic` where it was — not only the subset on the
candidates' `matched_identifiers`), `observation_context` (name, class,
segment, vendor, model, source kind, time) and `candidate_snapshots` (each
candidate as compared, keyed by asset id). Nothing is reconstructed from
`assets` afterwards — which matters most for a merge, where the survivor now
holds the observation's identifiers and a reconstruction would agree on
everything and hand the model its own label. `candidate_snapshots` is a
top-level list for the same reason: an executed merge rewrites `candidates`,
remapping the merged record onto the survivor and dropping it. When a pending
question is re-asked the stored view is the UNION of the sightings'
identifiers (A3's fold), so a sample describes every sighting that asked it.
`TestIntegration_ExportMergeDecisions` runs the script's own query over the
real engine and holds each exported pair, re-scored by the shipped model, to
the score the proposal recorded;
`TestIntegration_MergeProposal_PairScoreAndTrainingSampleSurviveTheMerge` does
the same through a real executed merge. Rows opened before v2 carry none of
those keys and are skipped, not guessed at.

The labels are a PERSON's decisions and nothing else:

- `kept_separate` → every candidate is `"match": false`;
- `merged` → a candidate is `"match": true` when it is the survivor
  (`merged_into`) or was itself merged into it (`assets.metadata.merged_into`);
  one that is neither is not labelled;
- a proposal with no `resolved_by` (a rule's merge, #2081 Phase 4) or with
  `auto_accepted` (the model's own) is skipped: training a model on its own
  decisions, or on the machinery's around it, is a feedback loop.


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
     still accurate and quietly untrue to it. Since v2 it also holds the four
     "hollow agreement" features (`name_generic`, `name_synthetic`,
     `id_match_derived`, `binding_conflict`) at ≤ 0;
   - `TestADerivedMatchIsStillEvidenceForTheMatch` and
     `TestBindingConflictDiscountsTheSharedAddress` — the two v2 statements a
     sign alone cannot make;
   - `TestAgreeingIsNeverWorseEvidenceThanDisagreeing` — the paired attribute
     features do not contradict each other. It is an ORDERING, not a sign,
     precisely because `vendor_match` is legitimately negative: the statement
     that has to hold is `vendor_conflict ≤ vendor_match`, and the same for
     model, class and segment. A retrain producing "different vendors is better
     evidence of sameness than the same vendor" keeps its accuracy, keeps its
     held-out score and satisfies the sign test, because neither feature is in
     either of its lists. `vendor_oui_*` joined
     it in v2;
   - `TestEveryFeatureIsExercisedByTheFixtures` — a new feature needs a fixture
     that sets it, or its weight is fitted on nothing.
5. Bump `model_id` if the change is one anybody should be able to tell apart in
   an audit. The id is written onto every proposal the model scores.
6. `cd ../.. && go test ./identity/...` — the vocabulary guard and the engine's
   integration with the seam.

## The pair score

When a sighting ties two records together — the MAC of one, the address of the
other — each candidate's score answers "is the SIGHTING this record?", while
the reviewer's real question is "are these two RECORDS one thing?". So
`Engine.rank` also scores the two top-ranked candidates against each other
(candidate A presented as the observation, B as the asset; every feature is
symmetric) and stores `pair_score`, `pair_asset_ids` and `pair_reason` on the
proposal. The Approvals card reads "the two records themselves score N%".

It is **advisory**. Nothing reads it to decide: not the auto-accept threshold,
not the same-device rule, not the executor (`TestPairScoreDecidesNothing` holds
a 0.99 pair score beside below-threshold candidates to no merge). Zero means
unscored — the null matcher, or fewer than two readable candidates. Two records
whose singletons disagree score at or under `SingletonConflictCeiling`. A
re-asked question keeps the higher pair score, like a candidate's.

## What it may never do

- **Decide.** ADR-0008 D5. The rule-based precedence walk of ADR-0002 D3 decides
  identity; this is consulted only on the conflict path, and only to rank. The
  pair score is evidence for a reviewer, and gates nothing either.
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
