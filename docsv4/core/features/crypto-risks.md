# Crypto Risks

Crypto risks are the weaknesses in the cryptography your estate is actually
negotiating: an obsolete protocol version, a broken cipher, a certificate that
cannot be trusted, a key too small for the job.

**Where:** **Risk & Compliance → Findings**. There is no separate Crypto Risks
page. Findings covers two different sets of results under the same chrome, and
the lens rail groups them so you always know which you are looking at:

| Group | Lenses | What it reads |
|---|---|---|
| **Platform findings** | By Producer · By Framework · By Control | The one findings table — compliance, end-of-life, vulnerability and every other producer |
| **Crypto findings** | By Severity · By Asset · By Category · By Date Observed | The crypto-risk stream described on this page |

The two are genuinely different data sets, which is why the counts jump when you
switch between the groups. That is not a miscount: an organization can have four
open compliance findings and nineteen crypto risks at the same time.

## The four crypto lenses

**By Severity** groups risks into Critical, High, Medium, Low and Informational
and shows the distribution across each group.

**By Asset** groups them by the host they were found on, which is how you
remediate — everything wrong with one box, fixed in one change window.

**By Category** groups by what kind of weakness it is:

| Category | What it covers |
|---|---|
| **Protocol** | Obsolete TLS/SSL versions, and SSH servers still speaking (or falling back to) SSH-1 |
| **Algorithm** | Weak or deprecated cipher suites and hash algorithms |
| **Certificate** | Certificate problems — expiry, weak signatures, validation failures |
| **Key size** | Keys below the accepted floor for their algorithm |

**By Date Observed** is a flat list, newest first, for "what changed this week".

## Working a risk

Each row shows the asset, the category, the issue, the **current value** that is
wrong (the thing to change), and when it was last observed. Above the list are a
search box and a severity filter; when a severity filter is active the page says
so in a banner rather than quietly narrowing the list.

Click a row to open the **inspector**, which carries the detail and the actions:

- **What is wrong and what to do about it** — the algorithm involved, its
  assessment, and the catalogue's migration guidance and recommended
  alternatives.
- **Create ticket** — opens a pre-filled ticket. It links the specific crypto
  configuration (`crypto_implementation_id`) and the asset, so the ticket tracks
  exactly this risk on exactly this service rather than "TLS on that box
  somewhere". Tickets appear in **Remediation → Queue**. The button needs the
  **Update compliance** permission; read-only users do not see it.

**Add to plan** and **Override control** are compliance-finding actions and are
not offered on a crypto risk — a crypto risk has no control to except. To group
crypto work into a migration plan, build the plan under **Remediation → Plans**.

**Export** produces a CSV of *the view you are looking at* — the current lens,
the current filters, the current search — with the asset, category, issue,
current value, severity, protocol, version and observation date. It does not
quietly export a different, wider dataset.

## Where the number comes from

Risk scores run 0–100. The **algorithm catalogue** supplies numeric component
assessments, and applicable deployment rules can also contribute. Browse the
catalogue under [Risk & Compliance → Posture → Algorithm Reference](algorithm-reference.md).

For each crypto configuration, numeric catalogue assessments of the linked
protocol version, cipher suite, key exchange, signature, symmetric and hash
algorithms contribute to the score. **The highest numeric contribution wins**;
a component with no numeric assessment contributes no invented number.

Cryptographic strength is a separate judgement. Crypto findings inspect every
relevant component's strength and applicable size/hash rules. A weak component
can justify a finding even with an explicit score of 0; an acceptable-only
assessment uses acceptable wording. Strong or recommended components alone do
not justify a weak-crypto finding merely because their numeric score is high.

The Algorithm Reference shows the catalogue's current strength, deprecation
status and risk score, including unscored rows. Finding evidence distinguishes
what justified the judgement from what set the numeric score. Deployment rules
can also contribute, and incomplete historical evidence may require reassessment
rather than support a fully reconstructable explanation.

Deployment-specific checks also apply, including:

- **Key size** — an RSA key below the NIST SP 800-131A 2048-bit floor is flagged
  regardless of the algorithm's own rating.
- **Certificate lifecycle** — expiry and validity problems have a separate
  lifecycle policy and alert stream.

An **explicitly assessed score of 0 is Informational**. Missing numeric
assessment is shown as *Not assessed*, not as zero. For legacy configurations,
a stored zero is corroborated only when linked risk-relevant catalogue
components have a maximum known numeric score of zero. Merely resolving a
component's name or strength is insufficient; a stored zero beside a current
catalogue score of 90 cannot establish an assessed zero.

Neither Informational nor a completed producer pass proves that all evidence was
scored. The **Why this score** panel and finding evidence expose the available
components and limitations. A known weak component with score 0 remains weak;
zero does not erase that qualitative judgement. See the
[rating upgrade guide](../operate/rating-upgrade.md) for legacy and API handling.

**Scores go down as well as up.** When you fix a service — disable TLS 1.0,
retire a weak cipher — the next discovery that sees it re-scores the
configuration from what it now negotiates, and the number falls, including all
the way to 0. The same is true when an assessment in the algorithm catalogue is
corrected downwards: the next observation of every configuration using that
algorithm picks the correction up.

One case leaves the number alone on purpose: a discovery that recognised
*nothing* about a configuration does not overwrite an earlier verdict with a 0.
It has no opinion to record, and silently replacing a real score with "not
assessed" would hide a risk you had already been shown.

### Severity bands

A score becomes a severity using the **CVSS qualitative severity ratings** (the
standard 0.0–10.0 scale, ×10):

| Severity | Score | Examples |
|----------|-------|----------|
| **Critical** | 90–100 | SSLv2, SSLv3, RC4, DES, MD5 signatures |
| **High** | 70–89 | TLS 1.0, TLS 1.1, 3DES, SHA-1, RSA-1024 |
| **Medium** | 40–69 | Expiring certificates, weak key sizes |
| **Low** | 1–39 | Minor configuration improvements |
| **Informational** | 0 | Explicit numeric assessment of zero; qualitative findings and coverage remain separate |

The same bands are used everywhere a risk level appears — the badges in
Inventory, the risk facet filter, the dashboard distribution, the counts here —
so a given score always reads the same way, whichever screen you are on.

### Seeing why a configuration scored what it did

You do not have to take the number on trust. Open any crypto configuration —
from **Inventory**, click a row, or open an asset and pick one of its
configurations — and the drawer's **Why this score** section lists every
component we resolved against the catalogue, worst first.

For each component you get:

- the **component's role** (protocol version, cipher suite, key exchange,
  signature, symmetric, hash) and its algorithm code;
- its **catalogue risk score and severity band**, or *not scored* when absent,
  plus the independently recorded strength and deprecation status;
- whether it was **observed in use** or only **offered, not observed** (see the
  SSH section below — offered algorithms still count);
- and, on the component that set the score, the catalogue's **migration
  guidance** and **recommended alternatives**.

The component that set the score is marked **sets the score**. Because the panel
reads the catalogue live, correcting an assessment in the catalogue changes the
explanation everywhere it appears — there is no separately stored copy to go
stale.

Honest-answer cases to expect:

- **"Not assessed."** A legacy stored zero is not assessed when linked
  catalogue evidence is missing, qualitative-only, or has a non-zero worst
  score. An explicit zero is shown as Informational only when the worst linked
  numeric catalogue contribution is also zero. Not assessed is not a clean bill
  of health — the available evidence could not establish a number.
- **Missing catalogue evidence.** No resolved components, or components
  carrying only qualitative assessments, cannot explain a numeric catalogue
  contribution. A positive stored score can still be displayed without claiming
  its original cause; a recognised algorithm can also have a known strength and
  no catalogue risk score.
- **A score higher than any single component.** When the stored score exceeds
  every current catalogue component, the panel identifies the gap without
  inventing its original cause. Catalogue values may have changed, or other
  checks may have contributed; this component evidence cannot determine which.

### Quantum vulnerability is decided by family

RSA at any key size and ECDSA on any curve are both breakable by a sufficiently
large quantum computer, and are flagged as needing post-quantum migration even
when the catalogue has no row sized to your exact key. Key size changes how
risky that key is *today*, not whether it eventually has to move off classical
asymmetric cryptography. This applies to certificates and to standalone keys
(**Inventory → Keys**) alike, and the framework that scores it is
[Post-Quantum Readiness](./compliance-frameworks.md#post-quantum-readiness).

### How SSH services are scored

SSH configurations are scored from the same catalogue as TLS, but SSH tells us
something TLS does not, so there is one extra distinction worth understanding.

An SSH server advertises **lists** of the key exchange, cipher and MAC
algorithms it will accept, and then one of each is chosen. We record both, and
they mean different things:

- **In use** — the protocol version (read from the server's version banner), the
  host key algorithm the server actually presented, and — when the discovery saw
  both sides of the handshake — the algorithms the handshake genuinely selected.
  These are what the crypto configuration's Key Exchange / Signature / Cipher /
  MAC fields show.
- **Offered** — everything else on the server's lists, shown as *inferred*. The
  server did not use it on this connection, but it will accept it.

**Offered algorithms count toward the risk score.** A server that still offers
`3des-cbc` or `diffie-hellman-group1-sha1` for legacy compatibility scores on
that offer, even if the connection we observed used something modern — because
any client can simply ask for the weak option. This matches how SSH auditing
tools report, and it is why hardening usually means *removing* algorithms from
the server's configuration rather than changing a preferred one.

Where a discovery only saw one side of the handshake (an active probe, or a
passive capture that started mid-connection), nothing is recorded as "in use"
beyond the banner and host key — everything else stays an offer rather than
being guessed at.

Algorithms are named exactly as SSH names them on the wire (`ssh-ed25519`,
`curve25519-sha256`, `aes256-gcm@openssh.com`, `hmac-sha2-256-etm@openssh.com`),
so a finding can be pasted straight into an `sshd_config` audit.

## When a risk appears, and when it goes away

Risks are re-derived as the inventory changes: when an asset is discovered, when
a configuration changes, when a discovery job completes, and when compliance
re-evaluates. Fix the service and the next observation of it re-scores the
configuration — there is nothing to mark resolved by hand.

A first assessment happens at ingest, so a newly discovered service is scored
immediately rather than waiting for a later pass: obsolete protocols, broken
ciphers, weak hashes and undersized keys are all recognised on the way in.

## Example remediation guidance

| Algorithm | Issue | Guidance |
|-----------|-------|----------|
| TLSv1.0 / TLSv1.1 | Outdated protocol | Move to TLS 1.2 or higher; check every client that still needs the old version first |
| SSLv3 | Broken protocol | Disable immediately — cryptographically broken |
| RC4 | Weak cipher | Disable RC4 cipher suites entirely |
| DES / 3DES | Weak cipher | Disable; replace with AES-GCM |
| MD5 | Weak hash | Migrate to SHA-256 or SHA-512 |
| SHA-1 | Weak hash | Migrate to SHA-256 or SHA-512 for hashing and signatures |
| RSA-1024 | Weak key | Re-key at 2048 bits minimum, 3072 or 4096 preferred |

The inspector shows the catalogue's own guidance for whatever it found, which is
always more specific than this table.

## API

| Endpoint | Returns |
|---|---|
| `GET /api/v1/inventory-service/crypto-risks` | The risk list, filterable by `severity` and `category`, paginated |
| `GET /api/v1/inventory-service/crypto-risks/summary` | Counts by severity, and how many assets are affected |
| `GET /api/v1/inventory-service/crypto-implementations/{id}/remediation` | The guidance for one crypto configuration |
| `GET /api/v1/inventory-service/remediation/algorithm/{code}` | The guidance for one algorithm |

## Related

- [Findings](./findings.md) — the page this lives on, and what the other lenses show
- [Algorithm Reference](./algorithm-reference.md) — every assessment, readable
- [Compliance Frameworks](./compliance-frameworks.md) — framework-scored posture, including Post-Quantum Readiness
- [Remediation](./remediation.md) — Alerts, the ticket Queue, and migration Plans
- [Inventory & Lenses](./inventory-and-lenses.md) — where the configurations themselves live
- [Discovery](./discovery.md) — how a configuration gets observed in the first place

## Legacy crypto-risk feed

The Findings crypto-risk feed keeps one row per configuration, including its
existing ticket link. Weak or acceptable catalogue judgments and applicable
key-size/hash rules decide whether a new row appears; numeric score alone does
not. A weak component scored 0 remains visible as Informational. A known
qualitative issue without a numeric assessment has a neutral, unscored grade.

The inspector separates the numeric score from its assessment basis, sources
and limitations. Certificate expiry is a separate lifecycle policy: within
30 days is Medium, and the remaining window through 90 days is Informational.
That grade does not manufacture a numeric score. Previously detected issues
remain visible when current evidence cannot refute them; deleting key-size or
hash facts does not establish that an earlier weakness was repaired.

The API emits canonical `info` and `low`, and nullable severity for unscored
issues; the old `informational` spelling remains a read-filter alias. List,
detail, summary and server export share this judgment. Summary severity buckets
count each asset at its worst emitted grade, while list rows are configurations.
Category membership can include several contributing issue types. The server
CSV export evaluates once, returns at most 50,000 rows, and includes numeric
score, assessment basis, sources and limitations alongside the original columns.
The Findings screen loads at most 500 rows and explicitly discloses truncation.
Its counts, filters and client export describe that loaded view, which remains
distinct from the server export.
