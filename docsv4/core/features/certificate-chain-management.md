# Certificate Chains

A certificate is only trustworthy because of what signed it, and what signed
*that*. The platform reconstructs those chains from the certificates it has, so
you can see a leaf's whole trust path — and, more usefully, see where the path
runs out.

## Where to look

**Inventory → Certificates**, click any certificate. The drawer that opens has an
**Issuer chain** section.

The chain is drawn as an indented list from the leaf downwards, each entry
labelled with the role it plays:

```
  certificate  www.example.com                  LEAF
  ↳ shield     Example Intermediate CA          INTERMEDIATE
    ↳ shield   Example Root CA                  ROOT
```

Certificate-authority entries carry a shield; the leaf carries a certificate
icon. Every entry is an identity the platform actually holds a record for — the
chain shows what is in your inventory, not what a server claimed.

If the top of the chain is not self-signed, a line appears beneath it:

> **Chain incomplete — issuer not in inventory.**

That is the useful state. It means the platform followed the chain as far as it
could and the next certificate up is one you do not have. It is not an error on
the leaf.

If nothing is linked at all, the section reads **No chain recorded**.

## What else the certificate drawer tells you

The chain is one section of six. The rest is the reason you usually open the
drawer in the first place:

| Section | What's in it |
|---|---|
| **Identity** | Common name, full subject, issuer, serial, and every subject alternative name. |
| **Validity** | Not before, not after, and days remaining. |
| **Key & signature** | Public key algorithm and size, signature algorithm, key usage, extended key usage. |
| **Issuer chain** | The trust path, as above. |
| **Trust & revocation** | Lifecycle state, OCSP status, whether it was logged to Certificate Transparency, whether its CA is known-bad, and how many places it is deployed. |
| **Fingerprints** | SHA-256 and SHA-1. |

The drawer header carries the headline facts as badges: the certificate's state,
how many days until it expires (or how long ago it did), and flags for
**self-signed** and **EV**.

## How chains get built

Two ways, and it is worth knowing which one you are relying on.

**A server that presents its whole chain gives you the chain.** When a scan or an
interrogation is handed a leaf plus its intermediates, the platform stores them
all and links them as it goes — in the order the server presented them, which is
the order that server intends. Most of your chains arrive this way and need
nothing from you.

**Anything else is matched and verified.** Where a certificate arrived on its own,
a chain rebuild works out what signed it:

1. **Look for the issuer by name.** Search your certificates for one whose subject
   matches this certificate's issuer, among those marked as CA certificates.
2. **Verify the signature.** A name match is a candidate, not an answer. The
   candidate's public key must actually verify this certificate's signature
   before anything is linked. Two CAs sharing a distinguished name is not
   hypothetical, and a chain built on names alone would quietly assert the wrong
   trust path.
3. **Link them,** and tell the rest of the platform, so compliance re-evaluates.

A self-signed root is recognised as the end of a chain and is not searched for.

A rebuild uses whatever is in your inventory *at the moment it runs*, so one
rebuild after importing a missing intermediate repairs every leaf beneath it at
once.

## Filling a gap

When a leaf's chain is incomplete:

1. Note the **Issuer** on the leaf — that is the certificate you are missing.
2. Get that intermediate's PEM from your CA.
3. **Inventory → Certificates → Upload cert.** Paste the PEM or pick the file.
   **Upload one certificate per file.** A file containing a whole chain is
   accepted, but only its first certificate is recorded — so upload the
   intermediate on its own rather than expecting a bundle to unpack itself.
4. Ask for the leaf's chain to be rebuilt, so it picks up what you just added
   (see below).

Uploading needs the **manage assets** permission, and the upload is capped at
1 MiB. The file is read for its contents rather than taken on trust — everything
shown about the certificate is extracted from the PEM itself.

### Rebuilding on demand

Adding an intermediate does not, on its own, relink leaves that were already in
inventory with a gap above them. Two API operations do that: rebuild one
certificate's chain
(`POST /api/v1/inventory-service/certificates/:id/rebuild-chain`, needs **update
assets**) or rebuild every unlinked chain in the organization
(`POST /api/v1/inventory-service/certificates/rebuild-all-chains`, needs **manage
assets**). The second reports how many chains it rebuilt, how many links it
created and how many chains are now complete — the one to use after a large
import from another system.

Neither has a button in the console today.

The chain itself is readable at
`GET /api/v1/inventory-service/certificates/:id/chain`, which returns the chain
from leaf to root, its length, and whether it is complete.

## Reading chains well

- **Incomplete is a statement about your inventory, not about the certificate.**
  A perfectly valid public certificate will show an incomplete chain until you
  have imported the intermediate that signed it.
- **Watch the intermediates' expiry, not just the leaves'.** An expiring
  intermediate takes every leaf beneath it down at once, and nobody has it in
  their calendar. The Certificates lens sorts by expiry; intermediates are in
  that list alongside everything else.
- **Self-signed is a chain of one, and that is correct.** A self-signed
  certificate has no issuer to find. Whether it *should* be self-signed is a
  different question, and the header badge is there so you notice.
- **Load your CA certificates first** when you are populating an inventory by
  hand, then run one rebuild across the organization. Doing it the other way
  round works too; it just costs you the same rebuild later.

## Related

- [Inventory and lenses](./inventory-and-lenses.md) — the Certificates lens and the drawer stack
- [Cryptographic keys](./cryptographic-keys.md) — the keys those certificates carry
- [Compliance frameworks](./compliance-frameworks.md) — the controls that judge certificates
- [Discovery](./discovery.md) — where most certificates come from
