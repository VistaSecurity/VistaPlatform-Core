# Disclaimer

**VistaPlatform is provided "AS IS" and is used entirely at your own risk.**

Please read this before deploying it, and before relying on anything it tells
you. It is not a substitute for the licence — see [LICENSE.md](LICENSE.md) for
the terms that actually govern your use, including the warranty disclaimer and
limitation of liability.

## Beta software

**VistaPlatform is beta software.** It is pre-1.0 and the version numbers say so.

- **Interfaces will change without notice** across 0.x releases — APIs, chart
  values, database schema, configuration, and the shape of the data model.
- **There is no supported upgrade path between arbitrary 0.x versions.** We do
  not promise that a release will upgrade cleanly from the one before it, or
  that your data survives the attempt.
- **There is no service-level agreement and no support commitment.** Issues are
  addressed as time allows.
- **Evaluate it before you depend on it.** Run it against a representative
  environment, confirm it does what you need, and keep your own backups.

None of this means it is unfinished as a product — it discovers, assesses, and
generates a CBOM today. It means the seams are still moving, and you should plan
for that rather than be surprised by it.

## No warranty, and use at your own risk

**THE SOFTWARE IS PROVIDED "AS IS" AND WITHOUT WARRANTIES OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING WITHOUT LIMITATION WARRANTIES OF FITNESS FOR A PARTICULAR
PURPOSE, MERCHANTABILITY, TITLE OR NON-INFRINGEMENT.**

**YOU ASSUME THE ENTIRE RISK OF USING IT — INCLUDING ANY DISRUPTION TO SYSTEMS
YOU SCAN OR INTERROGATE, ANY LOSS OR CORRUPTION OF DATA, AND ANY DECISION TAKEN
ON THE BASIS OF ITS OUTPUT. IN NO EVENT WILL THE LICENSOR HAVE ANY LIABILITY TO
YOU ARISING OUT OF OR RELATED TO THE SOFTWARE, INCLUDING INDIRECT, SPECIAL,
INCIDENTAL OR CONSEQUENTIAL DAMAGES, EVEN IF INFORMED OF THEIR POSSIBILITY IN
ADVANCE.**

The controlling text is the Disclaimer section of [LICENSE.md](LICENSE.md).
This page restates it for visibility; it does not add to it or take away from
it. Some jurisdictions do not allow certain exclusions, so parts may not apply
to you — in that case the exclusions apply to the fullest extent the law
permits.

## Authorized use only

VistaPlatform includes tooling that actively touches other people's
infrastructure. The sensor performs active TLS, SSH, SMB and OT/ICS probing when
you direct it to. The interrogation agent authenticates to network devices and
cloud accounts and reads their configuration.

**Only run it against infrastructure you own, or that you have documented
authorization to assess.**

- Scanning or probing systems without authorization may violate the Computer
  Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent laws
  elsewhere. Those are criminal statutes.
- Your cloud provider's acceptable-use policy may require notice or approval
  before scanning, even for infrastructure you own.
- Authorization from *your* organization is not authorization from a third
  party. Assessing a supplier, a customer, or a hosted service needs their
  agreement, in writing.

**Take particular care with OT and ICS.** Industrial control systems can behave
badly when probed — active scanning has disrupted production equipment in the
field. Test against a lab or a maintenance window before pointing anything at a
live plant network.

You are responsible for how you use this software. The licensor is not.

## Not compliance certification, and not legal advice

VistaPlatform's compliance evaluation, risk scores, post-quantum assessments and
CBOM artifacts are **informational output about your own systems**. They are not
an audit, an attestation, a certification, or legal advice.

- **Only an accredited body can certify you.** A PCI-DSS Report on Compliance
  requires a Qualified Security Assessor; a SOC 2 report requires a licensed CPA
  firm; ISO 27001 certification requires an accredited certification body. This
  software is none of those things, and passing every check in it does not make
  you compliant with anything.
- **Discovery is best-effort and structurally incomplete.** Passive capture sees
  only the traffic that crosses the sensor. Active probing sees only what it can
  reach and what answers. An empty result means nothing was found — never that
  nothing is there.
- **A risk score of 0 means NOT ASSESSED, not "safe."** Nothing resolved against
  the algorithm catalog and no rule fired. Treat it as a gap in coverage, not as
  a clean bill of health.
- **A CBOM describes what was discovered, at the moment it was generated**,
  within the scope predicate you defined. Its content hash proves the artifact
  has not been altered since. It does not prove the underlying inventory was
  complete.

Decisions about regulatory obligations, audit readiness, breach notification, or
cryptographic migration should be made with qualified professional advice.
Findings should be verified independently before you act on them.

## Third-party names and trademarks

Standards, frameworks, products and vendors are referred to by name only to
describe what this software does — nominative use. All such marks belong to
their respective owners.

**No affiliation, sponsorship, endorsement, certification, or approval by any of
them is claimed or implied**, including by the PCI Security Standards Council,
the AICPA, ISO, NIST, IEC, the IETF, the OWASP Foundation, or any device or
cloud vendor whose equipment this software can interrogate.

VistaPlatform's own marks are covered in [NOTICE](NOTICE).

## Cryptography and export control

This product uses cryptography and may be subject to export or import
restrictions in some jurisdictions. See the cryptographic notice in
[NOTICE](NOTICE).

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).
