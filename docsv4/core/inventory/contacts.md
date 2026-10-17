# Contacts and images

A **contact** is a person or a team you call about something: a NOC, an on-call rota, a
facilities manager, a vendor account rep. A **contact role** says what the contact is for on
one object: *Owner*, *Technical*, *Billing*, *On-call* and *NOC* come built in, and you can add
your own. An **assignment** puts a contact in a role on an object, with an optional priority
(*primary*, *secondary*, *tertiary* or *inactive*).

An asset's *Owner* line on the Overview is still just an email address kept for convenience;
it is not a contact, and the two are not linked.

## Manage contacts

**Settings -> Infrastructure -> Contacts** has two tabs.

- **Contacts**: add, edit and delete contacts. A contact has a name, an optional title,
  email, phone, address and link, and an optional **group** - another contact it belongs to,
  so a team can hold its members. Names are unique within a group.
- **Roles**: add, edit and delete your own roles. The built-in roles are marked *Built in*
  and cannot be changed. A role that is still assigned somewhere cannot be deleted.

Anyone with the DCIM read permission can see both tabs; changing anything needs
`dcim.manage`.

## Assign a contact

On an asset's **Overview** tab, the **Contacts** section lists who is assigned, primary
first, with each contact's role, priority, email and phone. With `dcim.manage`:

1. Choose **Assign contact**.
2. Pick an existing contact, or **New contact...** and type a name (and optionally an email)
   - the contact is created and assigned in one step.
3. Pick the role, and optionally a priority, then **Assign**.

The same contact can hold several roles on one object (an owner who is also the billing
contact), but not the same role twice. The remove button on a row removes that assignment
only; the contact stays. Deleting a contact removes all of its assignments.

Every assignment, edit and removal is recorded in the object's change log.

## Images

The **Images** section of the same tab holds pictures of the object: a photo of a rack
before the cabling work, a floor plan, a label. **Upload image** accepts PNG, JPEG, WebP and
SVG files of up to 5 MB; the type is decided from the file's contents, not its name, so a
program renamed to `.png` is refused. An SVG that contains a script, an event handler or an
embedded object is refused as well. Click a thumbnail to open the full image; the trash
button deletes the image and its stored file.

Images are kept in the object storage an administrator has configured for the platform
(artifact type `dcim_images`, enabled the same way as CBOM artifact storage). Until that is
enabled they are kept on the disk of the inventory service (`DCIM_IMAGE_DIR`), which is lost
if the pod is replaced without a volume mounted there.

## API

Under `/api/v2/inventory-service/dcim`: `contacts`, `contact-roles`, `contact-assignments`
(list, create, read, edit, delete), `objects/{kind}/{id}/contacts` (list and assign),
`objects/{kind}/{id}/images` (list and multipart upload), `images/{id}` (metadata, delete)
and `images/{id}/download` (the bytes). Reads need `dcim.read`, writes `dcim.manage`.
