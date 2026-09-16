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

Risk scores run 0–100 and come from the **algorithm catalogue** — the same
assessments you can read yourself under
[Risk & Compliance → Posture → Algorithm Reference](algorithm-reference.md).

For each crypto configuration we score every component we identified — the
protocol version, the cipher suite, and the individual key exchange, signature,
symmetric and hash algorithms — and **the worst component sets the score**. A
service is only as strong as the weakest thing it negotiates, so a strong
AES-256 cipher does not offset an RC4 fallback or a TLS 1.0 protocol version.

Because the score is read from the catalogue, you can always trace a number back
to a published assessment. Look up the algorithm in the Algorithm Reference and
you will see the same strength rating, deprecation status and risk score that
produced the finding.

Two things are scored outside the catalogue, because they depend on how an
algorithm was *used* rather than on the algorithm itself:

- **Key size** — an RSA key below the NIST SP 800-131A 2048-bit floor is flagged
  regardless of the algorithm's own rating.
- **Certificate lifecycle** — expiry and validity problems are their own
  findings.

A score of **0 means "not assessed"** — we did not recognise the cryptography in
use — which is deliberately different from "assessed and found safe". Those
configurations show as *Informational* and are worth investigating rather than
assuming clean. A configuration we *did* recognise and found nothing wrong with
also sits at 0; the **Why this score** panel is what tells the two apart, by
listing the components it resolved (or saying plainly that it resolved none).

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
| **Informational** | 0 | Not assessed — the cryptography in use was not recognised |

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
- its **catalogue risk score and severity band**, plus the strength and
  deprecation status the catalogue records;
- whether it was **observed in use** or only **offered, not observed** (see the
  SSH section below — offered algorithms still count);
- and, on the component that set the score, the catalogue's **migration
  guidance** and **recommended alternatives**.

The component that set the score is marked **sets the score**. Because the panel
reads the catalogue live, correcting an assessment in the catalogue changes the
explanation everywhere it appears — there is no separately stored copy to go
stale.

Two honest-answer cases to expect:

- **"Not assessed."** If nothing on the configuration resolved against the
  catalogue, the panel says so plainly. That is not a clean bill of health — it
  means we did not recognise the cryptography in use and could not judge it.
- **A score higher than any single component.** When the stored score exceeds
  every catalogue component, the panel says the remainder comes from checks the
  per-algorithm catalogue cannot express — chiefly key size — rather than
  implying the component list is the whole story.

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
