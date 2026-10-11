# Certificate Trust

A certificate is only as trustworthy as the authority at the top of its chain,
and *which authorities to trust is your organisation's decision*, not the
platform's and not any one sensor's. Vista Platform decides trust centrally, for
your organisation, from one list: the public root store it ships with, plus the
authorities you have explicitly trusted or distrusted.

That is what lets the inventory answer two questions a security team is always
asked: **which systems present self-signed certificates**, and **which present
certificates signed by an authority we never agreed to trust**.

## Why the platform decides, not the sensor

A sensor can only verify a chain against the trust store of the machine it runs
on. One sensor on a host whose operating system trusts your internal CA would
call a certificate valid; the Platform Sensor, running in a container that has
never heard of that CA, would call the same certificate untrusted. The answer
depended on who looked.

So agents only *observe* chains. Trust is evaluated by the platform, once, for
every certificate in your inventory, and every agent gets the same answer.

## Where to look

- **Settings → Policies → Trusted CAs** — the home of every decision.
- **Inventory → Certificates**, click any certificate — the drawer shows a
  **Trust** chip and, in **Trust & revocation**, which authority the decision
  was made on.
- **Risk & Compliance → Posture → Frameworks → Certificate Hygiene** — control CH-003 *Certificates are
  issued by a trusted CA* raises a finding for every certificate from an
  untrusted or distrusted CA, and closes it once you trust the CA.

Viewing needs the `assets.read` permission; recording or changing a decision
needs `certificates.trust`, which Tenant Administrators and Security
Administrators hold by default.

## What a certificate's trust status means

| Status | Meaning |
|---|---|
| **Public CA** | The chain ends at a root in the public root store the platform ships (the Mozilla root store, refreshed every release; the version is shown on the Trusted CAs page). |
| **Trusted (your CA)** | The chain passes through an authority your organisation explicitly trusted. |
| **Self-signed** | The certificate signed itself and is not an authority you trusted. Common on appliances and development systems; whether it *should* be self-signed is a question for the asset's owner. |
| **Untrusted CA** | The chain ends at an authority nobody has trusted — neither the public store nor your organisation. |
| **Distrusted CA** | The chain passes through an authority your organisation explicitly distrusted. This overrides the public store, so you can retire a root you no longer accept. |
| **Chain incomplete** | An issuer in the chain could not be found: not in inventory, not in the public root store, and not obtainable from the issuer URL the certificate itself names. No decision can be made yet. See [Certificate Chains](./certificate-chain-management.md). |
| **Not yet evaluated** | The certificate has been stored but trust has not been computed yet. The platform never shows a certificate as trusted by default. |

An explicit decision wins over the public store, and *distrust* wins over
*trust*: if any authority in a chain is distrusted, the certificate is
distrusted, whatever else the chain contains.

## Recording a decision

**From the Trusted CAs page.** Choose **Add CA**, paste the authority's
certificate in PEM form or pick the file, choose *Trusted* or *Distrusted*, add
a note if you want one (why, who asked, a ticket), and save. If you paste a
file with several certificates, the decision applies to the last one — the
top of that chain — and the others are stored so the chain is complete.

**From a certificate's own page.** Open any certificate-authority certificate
in **Inventory → Certificates**. Its drawer offers **Trust this CA** or
**Distrust this CA**. Use this when discovery has already seen the authority
— typically an intermediate that a server presented in its handshake — and you
want to mark it without finding the file.

Either way the effect is the same: every certificate in your inventory that
chains to that authority is re-evaluated at once, and the Trusted CAs table
shows how many certificates and assets the decision affects.

**Changing or removing a decision.** On the Trusted CAs page, **Change
decision** flips trusted to distrusted or back; **Remove** deletes the decision
and the affected certificates return to *Untrusted CA* — or *Public CA*, if the
authority is in the public store. The authority's certificate itself stays in
inventory.

## What this is not

- It is not a change to any device. Trusting an authority here tells the
  platform how to *classify* what it sees. It does not install anything on your
  hosts.
- Trust is independent of expiry, revocation and cryptographic strength. A
  certificate can be trusted and expired, or public and weak. Those are shown
  separately.

Related: [Certificate Chains](./certificate-chain-management.md),
[Assets and Crypto Configurations](./assets-and-crypto-configurations.md).
