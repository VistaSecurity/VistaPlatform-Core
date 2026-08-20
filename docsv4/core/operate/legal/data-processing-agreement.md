# Data Processing Agreement — template

> **This is a template, not legal advice.** It is written for the case where
> **you** run a Vista Platform deployment on behalf of someone else — a client,
> a group company, or the tenants of a managed service — which makes you their
> **processor** and them the **controller**. Replace every `[BRACKETED]` value
> and have counsel review the whole document before you sign it.
>
> If you run Vista Platform only for your own organization, you do not need
> this. See [when you need a DPA](./README.md#when-you-need-a-data-processing-agreement).
>
> The software author is **not** a party to this agreement and does not sign
> one: the software is self-hosted, and supplying software is not processing.

---

## Data Processing Agreement

This Agreement is entered into between:

**[CONTROLLER LEGAL ENTITY]**, of **[ADDRESS]** ("**Controller**"), and

**[YOUR LEGAL ENTITY]**, of **[YOUR ADDRESS]** ("**Processor**"),

and forms part of the **[NAME OF THE UNDERLYING SERVICES AGREEMENT]** between
them (the "**Principal Agreement**"). Where this Agreement and the Principal
Agreement conflict on the processing of personal data, this Agreement prevails.

### 1. Definitions

"Data Protection Law" means all law applicable to the processing under this
Agreement, including **[THE EU GDPR / THE UK GDPR / OTHER — LIST WHAT APPLIES
TO YOU]**. "Controller", "processor", "data subject", "personal data",
"processing", "personal data breach" and "supervisory authority" have the
meanings given to them in that law. "Sub-processor" means any processor engaged
by the Processor to carry out processing on the Controller's behalf.

### 2. Roles and scope

The Controller determines the purposes and means of the processing. The
Processor processes personal data only on the Controller's behalf, for the
purposes described in **Annex I**, and only for as long as the Principal
Agreement is in force or the law requires.

Each party is independently responsible for complying with Data Protection Law
as it applies to that party's own role.

### 3. Processing on documented instructions

The Processor processes personal data only on the Controller's documented
instructions, including as to international transfers, unless required
otherwise by law — in which case the Processor will tell the Controller before
processing, unless that law prohibits telling them.

This Agreement, the Principal Agreement, and the Controller's configuration of
the deployment together constitute the Controller's initial instructions.

**The Processor will tell the Controller if, in its opinion, an instruction
infringes Data Protection Law.**

### 4. Confidentiality

The Processor ensures that every person authorized to process the personal data
is bound by an appropriate obligation of confidentiality, contractual or
statutory, and that access is limited to those who need it to perform the
Principal Agreement.

### 5. Security

The Processor implements the technical and organizational measures set out in
**Annex II**, having regard to the state of the art, the costs of
implementation, and the nature, scope, context and purposes of the processing,
as well as the risk to data subjects.

The Processor may update those measures, provided the level of protection is
not reduced.

### 6. Sub-processors

The Controller gives the Processor **general written authorization** to engage
sub-processors, subject to this clause. The sub-processors engaged at the date
of this Agreement are listed in **Annex III**.

The Processor will give the Controller at least **[NUMBER — 14 OR 30 IS
CUSTOMARY]** days' notice before adding or replacing a sub-processor. The
Controller may object on reasonable data-protection grounds within that period;
if the parties cannot resolve the objection, the Controller may terminate the
affected part of the Principal Agreement without penalty.

The Processor imposes on each sub-processor, by contract, data-protection
obligations no less protective than those in this Agreement, and remains fully
liable to the Controller for the sub-processor's performance.

> **Note.** Self-hosting is what keeps this list short. Anyone whose
> infrastructure the deployment runs on is a sub-processor — cloud provider,
> managed database, backup destination, and any monitoring or log service the
> data reaches. The software author is not among them.

### 7. Assistance to the Controller

Taking into account the nature of the processing and the information available
to it, the Processor assists the Controller:

- **(a) With data subject requests.** The Processor will not respond to a data
  subject directly unless the Controller instructs it to, and will pass any
  request it receives to the Controller without undue delay. Assistance is
  provided by appropriate technical and organizational measures **so far as
  possible** — see §7.1.
- **(b) With security, breach notification, data protection impact assessments,
  and prior consultation** with a supervisory authority, under Articles 32 to
  36 of the GDPR or their equivalents.

#### 7.1 What assistance is technically possible

The platform serves **access and portability** requests directly: an
administrator exports everything held about one person as a structured file, and
that person can do the same for themselves without administrative help.

It serves **erasure** by anonymizing the person in place — the profile is
replaced with a placeholder, credentials and API tokens are deleted, and the
identity is removed from the activity trail — while **retaining** legal
acceptance records (as evidence of agreement), the activity trail itself (with
the identity removed), and the text of anything they authored. The reasons are
set out in the platform's operator documentation and should be reflected in the
Controller's own privacy notice.

**Erasure does not reach backups, personal data embedded in discovered
certificates or key material comments, or value snapshots inside older activity
entries.** Say so; a Controller who believes erasure was total will tell a data
subject something untrue.

Where the Controller's privacy notice commits to a response time, the parties
should agree here what the Processor undertakes:
**[AGREED RESPONSE TIME FOR ASSISTING WITH A REQUEST]**.

What the platform does provide, and which is usually what a request needs:

- Every asset, finding, certificate and audit record is scoped to a tenant and
  retrievable by tenant.
- An append-only audit trail across every service records who did what.
- Legal-acceptance records show which version of which document a user accepted,
  when, and from what address.

### 8. Personal data breach

The Processor notifies the Controller **without undue delay, and in any event
within [NUMBER — 24, 48 OR 72] hours** of becoming aware of a personal data
breach affecting personal data processed under this Agreement, providing at
least the information the Controller needs to meet its own notification duties,
as it becomes available.

The Processor does not notify a supervisory authority or data subjects about
such a breach on its own initiative, unless required by law.

### 9. Deletion or return

On termination of the Principal Agreement, and at the Controller's election,
the Processor **[DELETES / RETURNS]** the personal data and deletes existing
copies, within **[PERIOD]**, unless law requires it to keep them — in which
case it tells the Controller what it must keep and why.

Specify what happens to **backups**, which usually cannot be selectively
purged: **[STATE YOUR BACKUP RETENTION AND THAT DATA IS DELETED AS THOSE
BACKUPS AGE OUT]**.

### 10. Audits

The Processor makes available to the Controller the information necessary to
demonstrate compliance with Article 28 of the GDPR, and allows for and
contributes to audits, including inspections, conducted by the Controller or an
auditor it mandates.

The parties agree that audits will be **[NO MORE THAN ONCE PER YEAR EXCEPT
FOLLOWING A BREACH / AS AGREED]**, on **[NUMBER]** days' notice, during
business hours, subject to confidentiality, and at the Controller's cost unless
the audit reveals material non-compliance.

### 11. International transfers

The Processor does not transfer personal data outside **[JURISDICTION]** except
as set out in Annex III or on the Controller's instruction, and only where a
valid transfer mechanism is in place — an adequacy decision, Standard
Contractual Clauses, or another lawful mechanism identified here:
**[MECHANISM]**.

### 12. Liability, term and governing law

The liability caps, term and governing law of the Principal Agreement apply to
this Agreement. **[CONFIRM THIS IS WHAT YOU INTEND — SOME CONTROLLERS REQUIRE A
SEPARATE OR UNCAPPED DATA-PROTECTION LIABILITY REGIME.]**

**Signed:**

| Controller | Processor |
|---|---|
| Name: **[NAME]** | Name: **[NAME]** |
| Title: **[TITLE]** | Title: **[TITLE]** |
| Date: **[DATE]** | Date: **[DATE]** |

---

## Annex I — Details of the processing

**Subject matter.** Operation of a Vista Platform deployment for the
Controller: discovery, inventory and compliance assessment of the cryptographic
assets in the Controller's estate.

**Duration.** For the term of the Principal Agreement, plus the deletion period
in §9.

**Nature and purpose.** Hosting and operating the deployment; discovering
network endpoints, certificates, keys and cryptographic configurations;
evaluating them against compliance frameworks; producing findings, reports and
Cryptographic Bills of Materials; providing support.

**Categories of data subjects.**

- The Controller's personnel who hold accounts in the deployment
- **[ANY OTHER CATEGORY — E.G. THE CONTROLLER'S OWN CUSTOMERS, IF THEIR SYSTEMS
  ARE IN SCOPE]**

**Categories of personal data.**

| Category | Examples |
|---|---|
| Account data | Name, work email address, role, authentication credentials (hashed), SSO subject identifier |
| Usage and security records | Audit trail entries, sign-in events, IP address and user-agent, legal-acceptance records |
| Contact data in tickets and notifications | Assignee and commenter identity, notification destinations |
| Incidental personal data in discovered configuration | Certificate subject and SAN fields, SSH key comments, hostnames and device names that identify a person |

> That last row is the one people forget. Discovery data is mostly about
> machines — but a certificate issued to `firstname.lastname@example.com`, or
> an SSH key commented with an engineer's name, is personal data, and it arrives
> automatically rather than by anyone entering it.

**Special category data.** None is required or intentionally processed.
**[STATE ANY EXCEPTION, OR CONFIRM NONE.]**

**Frequency.** Continuous, for the term.

---

## Annex II — Technical and organizational measures

These describe the measures **the platform provides as shipped**, at its
default settings. The Processor is responsible for the measures around it —
infrastructure, access control, backups, monitoring and staff — and for not
disabling the ones below.

**Verify each row against your own deployment before signing.** Several are
configurable, and a measure you have turned off is a measure you cannot claim.

| Area | Measure as shipped |
|---|---|
| **Tenant isolation** | PostgreSQL row-level security on 133 tables, enforced by default. Services connect as a role that owns nothing and does not hold `BYPASSRLS`, so a query without tenant context returns no rows. 19 views run with `security_invoker` so they cannot be used to read around it. |
| **Encryption in transit — external** | TLS at the ingress. Certificate supply is the operator's: cert-manager, an existing secret, or a self-signed certificate for evaluation only. |
| **Encryption in transit — internal** | Mutual TLS between services by default, using per-service certificates from a private CA the deployment provisions, rotated automatically on a 90-day cycle. PostgreSQL connections require TLS and verify the server certificate; NATS requires a client certificate. |
| **Encryption at rest — credentials** | Integration, device and cloud credentials are encrypted with AES-256-GCM under keys derived by HKDF from a master key held outside the database. |
| **Password storage** | Argon2id. |
| **Authentication** | httpOnly session cookies with paired CSRF tokens; JSON Web Tokens verified with the key chosen by algorithm class, rejecting `alg: none`; refresh-token rotation with reuse detection; scoped API tokens for programmatic access. |
| **Authorization** | Role-based access control with 36 distinct tenant permissions, enforced in the services rather than only in the interface. Platform-administration routes are served on a separate host and denied on the tenant-facing one. |
| **Auditability** | Every service writes to a central append-only audit trail. Legal acceptances record the document version, its content hash, the time, and the observed IP and user-agent. |
| **Data minimization in discovery** | Collectors project vendor responses onto an explicit allowlist of fields, and a redaction layer wraps every device interrogator, so key material, pre-shared keys and passwords encountered on a device are not stored. The platform records *what cryptography is in use*, not the keys it is used with. |
| **Supply chain** | Container images are built from public source in CI and signed with Sigstore; release binaries are published with signed checksums. Verification instructions ship with each release. |
| **Segregation of environments** | The operator's responsibility. Nothing in the platform requires production and non-production to share a deployment, and they should not. |

**Measures the platform does *not* provide, which the Processor must supply:**

- **Backup and restore.** The platform performs no automated backups. Backup,
  restore testing and backup encryption are entirely the operator's.
- **High availability.** Datastores are single-replica by default. Availability
  commitments require the operator to change that and to run the infrastructure
  behind it.
- **Retention and deletion beyond a data subject request.** The platform serves
  access, portability and erasure on demand (§7.1) but does not expire data on a
  schedule.
- **Retention enforcement.** Retention periods stated in a privacy notice must
  be implemented operationally; the platform does not expire data on its own.
- **Physical and infrastructure security, personnel screening, and security
  training.** These belong to the operator and their hosting provider.

---

## Annex III — Authorized sub-processors

| Sub-processor | Role | Location | Transfer mechanism |
|---|---|---|---|
| **[NAME]** | **[E.G. INFRASTRUCTURE HOSTING]** | **[COUNTRY]** | **[ADEQUACY / SCCs / N/A]** |
| **[NAME]** | **[E.G. MANAGED DATABASE]** | **[COUNTRY]** | **[…]** |
| **[NAME]** | **[E.G. OFFSITE BACKUP]** | **[COUNTRY]** | **[…]** |

**If there are none — because you run this entirely on your own
infrastructure — say so explicitly** rather than leaving the table empty. An
empty table reads as an oversight; "there are no sub-processors" is a statement
the Controller can rely on.

### Destinations that are not sub-processors, but are still data flows

These leave the deployment because the Controller configured them, and they
belong in the Controller's own records even though the Processor does not
contract with them:

- SIEM forwarding, CMDB and ITSM synchronization, ticketing systems, and
  notification channels (email, chat, webhooks) that the Controller has enabled.
- **AI assistants connected through the platform's read-only MCP endpoint.** If
  a user creates an API token and authorizes an assistant, what that assistant
  reads is processed by whichever AI provider they chose, under that provider's
  terms. **[STATE WHETHER YOU PERMIT THIS.]**
