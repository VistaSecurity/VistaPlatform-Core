# Shared crypto assessment

`Configuration.Judge` is the pure qualitative gate used by the crypto producer
and the live `/crypto-risks` read feed. Every linked catalogue component can
justify a weak or acceptable judgment independently of the highest numeric
score. Key-size and hash rules use `shared/cryptoparse`. Neither a positive
number nor missing evidence alone creates a new weak-configuration row.

`Configuration.Score` returns the maximum available catalogue, positive legacy
stored, deployment-rule, and still-unrefuted historical finding contribution. A known catalogue zero remains zero;
missing numeric evidence remains nil. `ScoreSources` names tied contributors
and labels persisted values as lacking their original rule provenance. The
producer retains its existing integer writer contract and evidence limitations;
that compatibility zero must not be treated as proof of numeric assessment.
PQC classification remains a separate domain using the existing shared CTE.

## Live read contract

The feed keeps one row per configuration and its existing configuration UUID,
including ticket links. It resolves the asset through the current endpoint
owner and includes monitoring assets only. The producer also judges pending
approval assets so approval has evidence; this read view deliberately does not.
All reads run in a tenant-scoped transaction and never invoke a producer write.

The emitted numeric severity is canonical `critical/high/medium/low/info` and
nullable for a known qualitative issue without a numeric assessment. Only the
read filter accepts historical `informational` as an alias for `info`;
`unscored` selects null and is not a new severity rung. Low is a real band.

Certificate expiry is separate lifecycle policy in this mixed legacy feed:
future expiry within 30 days is Medium; the remaining window through 90 days is
Info. It supplies no invented numeric score and remains independent of the
configuration's `risk_score`. Expired-certificate handling remains in the
certificate alert domain. `assessment_basis` identifies the selected judgment;
`assessment_limitations` and `score_sources` explain the available evidence.

An existing active weak-configuration finding may be retained when missing
facts prevent reassessment. Deleting key/hash facts cannot refute an older
weakness, even when the current catalogue score exceeds the historical score.
Bounded unresolved role/rule obligations remain in existing finding evidence
(no raw snapshot chain) until affirmative applicable
replacement facts can reassess it; observing and repairing a different weakness
does not erase that gap. A signature/key family alone cannot establish a hash;
this conservative historical adapter requires an observed, resolved hash role.
Such rows identify `retained_finding`, explain the
historical basis, and stop appearing once complete current evidence refutes the
issue. A legacy positive configuration score alone does not establish this
history. Historical zero without recorded numeric sources stays unscored.
The read projection never mutates the finding's stored lifecycle or evidence.

List filters, count, detail, export and summary use the same judged population.
Severity summary buckets count assets once at their worst emitted severity;
`unscored` counts affected assets with no graded emitted issue. The current UI
loads at most 500 rows and explicitly discloses truncation; its counts, filters
and client CSV refer to that loaded prefix. Protocol,
algorithm and key-size counters count configurations; the existing certificate
counter continues counting certificate inventory rows, including unlinked
certificates. A configuration can contribute to several issue categories.

The list pushes tenant, asset status, detail ID and search into SQL. It streams
all candidate facts in one query (no application-level N+1), keeps only the
best offset+page-size rows in a heap, and uses configuration UUID as a stable
sort tie-breaker. Each stateless page still evaluates the matching candidates;
there is no new cache or provenance store. Export evaluates once, preserving
the existing 50,000-row ceiling. Its original CSV columns stay in place and
numeric score, basis, sources and limitations are appended. Empty score/severity
cells retain missing assessment. The 2,000-configuration Postgres regression
checks page/export ordering and logs timings without asserting machine speed.
