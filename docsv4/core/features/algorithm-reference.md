# Algorithm Reference

The **Algorithm Reference** is a read-only catalogue of every cryptographic algorithm the platform knows about, together with our assessment of each one — how strong it is, whether it's deprecated, whether it resists quantum attack, and what to migrate to. It's the same source-of-truth rating the platform uses to flag risk across your inventory, made visible so a "weak" or "deprecated" verdict is something you can understand and act on, not just take on faith.

## Where to find it

**Risk & Compliance → Posture → Algorithm Reference** tab.

Anyone who can view the Posture page can browse it — no special permission required.

## What you can do

### Browse and filter

The tab opens on the full catalogue, sorted with the highest-risk algorithms first. Narrow it with:

- **Search** — match on name, code, family, or primitive (e.g. `RSA`, `ML-KEM`, `aead`).
- **Strength** — Recommended / Strong / Acceptable / Weak.
- **Status** — Current / Deprecated / Obsolete.
- **Quantum** — PQC (post-quantum) vs Classical.

Each row shows the algorithm's family, type, strength, deprecation status, whether it's post-quantum, and a risk score (0–100, higher is worse).

**Protocol-specific spellings.** Where a protocol names its algorithms on the
wire, the catalogue uses that exact name so a finding matches what you would
type into the server's configuration. SSH is the clearest example — search for
`ssh-`, `hmac-`, `curve25519` or `@openssh.com` and you'll find the SSH host
key, MAC and key exchange algorithms under the names `sshd_config` uses
(`ssh-ed25519`, `diffie-hellman-group14-sha1`, `aes256-gcm@openssh.com`).
Protocol-independent entries (`AES256`, `SHA256`, `Ed25519`) sit alongside them.

### Open an algorithm for the full assessment

Click any row to open a detail panel with:

- **Our assessment** — strength, deprecation status (and date, if set), risk score, and post-quantum standardization status.
- **Migration guidance** — our plain-language recommendation, plus the specific **recommended alternatives** to move to.
- **Identity & parameters** — the technical detail (family, primitive, mode, padding, curve, parameter set, classical/quantum security levels, OID, and crypto functions) for anyone who needs it.

## How this connects to the rest of the platform

When the platform marks an asset, certificate, or configuration as risky because of the algorithm it uses, the reasoning lives here. The Algorithm Reference is the "why" behind those flags — and the **Frameworks** tab next to it explains the *compliance* side the same way: which controls you're measured against and exactly what each one checks.

This is literal, not a figure of speech: the risk score shown on a crypto
configuration **is** the risk score of its worst component algorithm, read from
this catalogue. If a finding says a service is High risk, you can look the
algorithm up here and see the assessment that produced it. See
[Crypto Risks → Risk Score Calculation](crypto-risks.md#risk-score-calculation).

> The assessment is maintained by the platform. Tenants view it; they don't edit it. Platform administrators manage these ratings centrally so every tenant is measured against the same standard.
