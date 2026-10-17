---
render_macros: false
---

# Maintenance in the Admin Console: Back Up, See What's New, Update

The admin console has a **Maintenance** section (left rail, **Platform** group) with
two pages:

- **About & Updates** shows which version of each service is running, whether a newer
  Vista Platform release exists, and updates the platform.
- **Backups** takes a backup of the platform database, optionally with the encryption
  keys a restore needs, and keeps the newest few for you to download.

Everything on this page is part of Vista Platform Core. Enterprise and MSP installs use
the same pages.

These pages work on installs made with the **Helm chart** on Kubernetes. A Docker
Compose install (evaluation only) shows "Not available in this deployment"; back that
database up with `pg_dump`. If the Maintenance section is missing altogether, it has been
turned off; see [Turning it off](#turning-it-off).

> **Who can use it.** Anyone who can see System Health can read these pages. Taking,
> downloading and deleting a backup, checking for updates and running an update need
> the separate permission `platform.maintenance`, which the built-in Platform
> Administrator role has. See [Permissions](#permissions).

---

## Backups

### Create a backup

1. Sign in to the admin console and open **Maintenance → Backups**.
2. Choose **Create backup**.
3. Decide whether to tick **Include encryption keys and install secrets** (see the next
   section). If you do, enter a passphrase of at least 12 characters twice.
4. Choose **Create**. A row appears as "Running". The platform keeps working while the
   backup runs. When it finishes the row says "Ready" with its size.

Only one backup (or other maintenance run) can run at a time. **Run history**, below the
list, records who started each backup and update, when, and how it ended. A failed run
keeps the end of its log so you can see why.

### What is inside a backup

Every backup holds the platform database (`crypto_inventory`), taken with
`pg_dump` in custom format, plus a small `manifest.json` that says which version took it.
What you download depends on the tick box:

| Option | File you download | Contains |
|---|---|---|
| Keys **not** included | `vista-platform-backup-<date>-<version>.tar` | `manifest.json`, `database.dump` |
| Keys included | `vista-platform-backup-<date>-<version>.enc` | the same two files plus `secrets.yaml`, **encrypted with your passphrase** |

- `database.dump` is everything in the platform database: tenants, inventory, findings,
  configuration. It is **not** a copy of any keys.
- `manifest.json` records the Vista Platform and chart versions, the database schema
  version, the edition, the install ID and the Helm release name and namespace.
- `secrets.yaml` holds the install's Kubernetes Secrets: the encryption master key, the
  JWT signing key, the install identity, the generated database, Redis and NATS
  passwords, and the key that signs CBOM artifacts.

### Do you need the keys?

Tick the box if you ever want to restore onto a fresh install and have it behave like
the old one. Without the keys:

- Credentials the platform stored encrypted (integration and device credentials,
  collector agent secrets) cannot be decrypted. You re-enter them and re-enroll the
  collectors.
- Everyone is signed out, because the JWT signing key is new.
- CBOM artifacts signed before the backup no longer verify.
- The install identity is new, so an install-bound licence must be re-issued.

> **Warning: the passphrase is not stored anywhere.** Not in the platform, not in the
> database, not in the backup. It is the only way to open an encrypted backup. If you
> lose it, that backup cannot be restored and Vista Security cannot recover it. Keep it
> in your password manager, separately from the file. The encrypted file contains your
> install's master keys: treat it, and the passphrase, as you would the cluster's
> Secrets.

The encryption is AES-256-GCM with a key derived from your passphrase using Argon2id.
The keys are never served unencrypted; that is why a passphrase is required.

### Download, retention and delete

- **Download** streams the file to your browser. A backup that lives only on the
  platform's own volume is not off-site, so download it and keep it somewhere else.
  Every download is recorded in the activity trail.
- **Retention.** The newest `maintenance.backups.retention` ready backups are kept
  (default 5). After each new backup the oldest beyond that are removed.
- **Delete** removes one backup now.

### Where backups are stored

Backups are written to a volume the chart creates for the maintenance service. The
chart values (`maintenance.backups.*`):

| Value | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` creates no volume; the page says "Backup storage is not configured" |
| `size` | `20Gi` | Size of the volume. Make it at least a few times your database size times the retention |
| `retention` | `5` | How many ready backups to keep |
| `storageClassName` | empty | Empty uses `datastores.storageClassName` |
| `accessMode` | `ReadWriteOnce` | `ReadWriteOnce` or `ReadWriteMany` |

With the default `ReadWriteOnce`, only one node can mount the volume at a time, so the
backup runs on the **same node** as the maintenance service and the service restarts
without a surge pod (the old one lets go of the volume before the new one starts). That
works with no action from you; it matters only if that node is full or drained, when a
backup may wait for room. A `ReadWriteMany` storage class removes both limits.
`ReadWriteOncePod` does not work and the chart refuses it.

`helm uninstall` keeps the volume, so removing the platform does not delete your
backups.

### External databases

If you run PostgreSQL yourself (`datastores.postgres.enabled=false`), backups work the
same way: the backup job dumps the database named by the platform's `database-url`
Secret. The database user must be allowed to read everything in `crypto_inventory`.
The job runs `pg_dump` from the chart's `schemaMigration.image` (PostgreSQL 17), and the
database must be reachable from the cluster namespace.

### Restore

Restoring is a documented procedure, not a button, in this release. It puts a backup
onto a **fresh install of the same version**, then you upgrade normally.

You need: the backup file; its passphrase if it is an `.enc` file; `kubectl` and `helm`
pointed at the target cluster; and your own values file. If you have never used
`kubectl`, ask whoever installed the platform to run the commands below with you; every
step says what it does.

1. **Open the file.** For an `.enc` backup, decrypt it with the `bundle-decrypt` tool.
   It is built from this repository (Go 1.26 or newer, from a checkout of the release
   tag you are running):

   ```bash
   cd services/maintenance-service
   go build -o bundle-decrypt ./cmd/bundle-decrypt
   ```

   This builds the tool. Then decrypt (the passphrase is read from the environment so it
   does not appear in your shell history or process list):

   ```bash
   VISTA_BACKUP_PASSPHRASE='your passphrase' ./bundle-decrypt \
     -in vista-platform-backup-20261014-031200-4.6.0.enc -out bundle.tar
   ```

   This writes the tar inside the backup. A wrong passphrase, or a file that was cut
   short or changed, fails with an error and writes nothing. A `.tar` backup needs no
   decryption.

   ```bash
   tar -xf bundle.tar
   cat manifest.json
   ```

   This unpacks `manifest.json`, `database.dump` and, for an encrypted backup,
   `secrets.yaml`. In `manifest.json` note `chart_version`, `release.name` and
   `release.namespace`. Use those same values below.

   Delete the unpacked `secrets.yaml` and `bundle.tar` when the restore is finished.

2. **Put the Secrets back first (encrypted backups only).** Do this before installing,
   so the new install keeps your original keys instead of generating new ones:

   ```bash
   kubectl create namespace <namespace>
   kubectl apply -n <namespace> -f secrets.yaml
   ```

   The first command creates the namespace; the second recreates the Secrets with their
   original values. Their Helm labels let the install adopt them. Use the **same release
   name and namespace** as `manifest.json`; a different namespace makes Helm refuse the
   Secrets ("invalid ownership metadata"). For a `.tar` backup, skip this step and expect
   the consequences listed under [Do you need the keys?](#do-you-need-the-keys).

3. **Install the same version.**

   ```bash
   helm install <release> oci://ghcr.io/vistasecurity/vistaplatform \
     --version <chart_version> -n <namespace> -f <your values file> --wait --timeout 30m
   ```

   This installs a clean platform with an empty database, as for any new install. Use the
   chart source and values you normally install with.

4. **Stop everything that writes to the database.**

   ```bash
   kubectl -n <namespace> scale deployment --all --replicas=0
   ```

   This stops all the services. PostgreSQL keeps running, because it is a different kind
   of workload.

5. **Replace the database.** Drop the new, empty database and create it again, then load
   the dump into it:

   ```bash
   kubectl -n <namespace> exec postgres-0 -- psql -U <database user> -d postgres \
     -c 'DROP DATABASE crypto_inventory WITH (FORCE)' \
     -c 'CREATE DATABASE crypto_inventory OWNER <database user>'
   ```

   This deletes and recreates the database. `<database user>` is
   `datastores.postgres.user` from your values.

   ```bash
   kubectl -n <namespace> exec -i postgres-0 -- pg_restore \
     -U <database user> -d crypto_inventory --exit-on-error < database.dump
   ```

   This streams the dump into the empty database. It must finish with no errors.

   > **Drop and recreate the database. Do not use `pg_restore --clean`** over the fresh
   > install's database: it cannot drop the partitioned tables' constraints and reports
   > dozens of errors.

   With an external database, run the same two commands against it from any machine with
   PostgreSQL 17 client tools, replacing `-U … -d …` with the connection string
   (`-d "$DATABASE_URL"`); dropping the database needs its owner or your provider's
   administrator login.

6. **Start the platform again.**

   ```bash
   helm upgrade <release> oci://ghcr.io/vistasecurity/vistaplatform \
     --version <chart_version> -n <namespace> --reuse-values --wait --timeout 30m
   ```

   This brings the services back with their normal replica counts. The chart version is
   unchanged, so `--reuse-values` is safe here. If you want a newer version, restore
   first and update afterwards, as in [Updates](#updates).

7. **Check it.**
   - In the admin console open **Maintenance → About & Updates**: every service should
     show the backup's version and "All services aligned".
   - Sign in as a tenant user. An integration with a stored credential should still
     connect, which proves the master key came back.
   - The backup run that was in progress when the dump was taken is marked "failed" on
     the first start. That is expected and needs no action.

Restoring into the **same** release name and namespace is the supported path. Restoring
across versions is not: restore into the version in `manifest.json`, then update.

---

## Updates

### Knowing a new release exists

When a newer Vista Platform release is available, every admin console page shows a
banner under the top bar: "Vista Platform 4.6.0 is available · What's new". You can
dismiss it; it comes back for the next version. It appears only for users who may see
System Health, never for tenants.

**Maintenance → About & Updates** is the full picture:

- **Running versions** lists each service and the version it runs, with a badge:
  *All services aligned*, *Version skew detected* (two services report different
  versions, usually an interrupted upgrade), *Degraded* (aligned but a service cannot be
  reached) or *Version unknown*.
- **How this install is managed** says whether the console can update this install
  (see [Installs managed outside Helm](#installs-managed-outside-helm)).
- **Updates** says "Up to date · checked 2 hours ago", or "Vista Platform 4.6.0
  available" with a **What's new** link to the release notes, or why the check could not
  run. **Check now** runs a check immediately.

### Where "latest" comes from

The platform lists the version tags of the chart's repository in the OCI registry it was
installed from, picks the newest release, and compares it with what is running. The
registry is derived from your image settings (`image.registry` and `image.repoPrefix`),
so an install that pulls from your own mirror checks your mirror. It is anonymous unless
your first `image.pullSecrets` entry has a credential for it. Nothing about your install
is sent anywhere else.

Override the repository with `maintenance.chartSource` if the chart lives somewhere
other than the images, for example `oci://registry.example.internal/vistaplatform`.

| Value | Default | Meaning |
|---|---|---|
| `maintenance.updateCheck.enabled` | `true` | `false` stops the periodic check and refuses a manual one: no outbound call is made |
| `maintenance.updateCheck.interval` | `24h` | How often to check (a duration such as `12h`; minimum `1m`) |
| `maintenance.updateCheck.includePrereleases` | `false` | `true` also offers release candidates (for example `4.6.0-rc.1`) |
| `maintenance.updateCheck.notesBaseUrl` | the Vista Security release-notes page | Root of the release-notes page for sources other than `ghcr.io`; the version is appended |
| `maintenance.chartSource` | derived from `image.*` | OCI repository to check and to update from |

Release notes for the Core line are the GitHub Release of the public repository.

**Air-gapped sites.** Set `maintenance.updateCheck.enabled=false` so the platform makes
no outbound call; the Updates card then says "Update check is off". Mirror the chart and
images into your own registry as described in `INSTALL.md`, point `image.registry` (and
`maintenance.chartSource` if needed) at the mirror, and either leave the check on
against the mirror, which works the same way, or turn it off and update on your own
schedule.

### Updating from the console

When an update is available, **Update to 4.6.0** on the Updates card opens the update
dialog. You need `platform.maintenance`.

1. **Pre-flight checks.** The dialog first checks the install and lists every result, so
   you can fix everything in one pass. A *Blocks the update* result must be fixed before
   **Update** is enabled; a *Warning* does not stop you.

   | Check | Outcome | What it means |
   |---|---|---|
   | Managed by Helm | Blocks if not | Helm manages the install and no GitOps controller owns it. Otherwise see [Installs managed outside Helm](#installs-managed-outside-helm) |
   | Version available | Blocks if not | The version is published at the chart source and newer than the running one |
   | Chart signature | Blocks if it fails; **Warning** when verification is turned off | The chart's cosign signature matches the Vista Security release identity |
   | Image pins in your values | Warning | A `image.tag`, `backends.<service>.image.tag` or `image.digest` you set (often for a hotfix) is carried into the update, so that service would stay on the pinned image. The warning names them; remove them first unless the pin is intended |
   | Cluster size | Warning on a single node | A rolling update starts each new pod before the old one stops, which can need more CPU than one node has and stall the update. The warning lists the services that roll rather than recreate |
   | Database schema | Warning | The schema marker could not be read, or was last written by a different chart than the running one (a previous update may not have finished) |
   | No other maintenance running | Blocks if one is | A backup, update or rollback is already in progress |
   | Recent backup | Warning if none | Whether a ready backup from the last 24 hours exists. The update takes its own fresh one regardless, unless you tick the box below. With backup storage turned off it warns that you must back up yourself |

2. **Confirm.** The dialog lists what will happen and asks you to type the version
   number to enable **Update**.

3. **Backup first.** Every update starts with an automatic backup of the database. It is
   database only: it does **not** include the encryption keys. If you want a backup with
   the keys, take one from Backups first. Tick **I have my own backup — skip the backup
   step** to skip it; the run records that step as skipped by the operator. On an install
   with backup storage turned off (`maintenance.backups.enabled=false`) the console
   refuses to start an update unless that box is ticked.

4. **The run.** The progress page walks through four steps with a live log: *Back up the
   database*, *Verify the chart's signature*, *Upgrade: apply the schema and restart every
   service*, and *Check every service runs the new version*. The upgrade step runs as a
   Kubernetes Job, not inside the console, as
   `helm upgrade <release> <chart source> --version <version> --reset-then-reuse-values --wait --timeout 30m`,
   the same command as the manual procedure. Only one maintenance run can be active; starting
   a second is refused.

5. **Expected downtime.** Services on the default rolling strategy keep serving while
   new pods start, but each waits for the database schema migration to finish, so an
   update that changes the schema takes as long as the migration plus the rollout.
   Services set to `strategy: Recreate` (such as `pcap-processor` and `sensor-manager`) are
   unavailable for that whole window. The admin console restarts too: the progress page
   shows "Services are restarting — this page will reconnect" and keeps trying for up to 15
   minutes. The update carries on without it, so you can close the page and come back; the
   run is also in **Run history**.

6. **Done or failed.** On success the page says "Running Vista Platform 4.6.0" and the
   banner goes away. On failure it shows the step that failed with the end of its log.
   - If it failed at the **backup** or **signature** step, the page says nothing was
     changed and your current version is still running.
   - If it failed at the **upgrade** or **version check** step, the cluster may have
     changed and the page offers **Roll back to 4.5.0**.

   Change a chart value such as `maintenance.updates.timeout` (default `30m`, a whole
   number of `s`, `m` or `h`) if a large install needs longer than 30 minutes to roll.

### Rolling back

**Roll back** runs `helm rollback` to the previous release revision in a Job, then checks
every service runs that version. It returns the Kubernetes side (images and configuration)
to the previous release. It does **not** undo the database: the schema changes are additive,
and the previous version runs on the newer schema. If you need the database as it was
before the update, restore the backup the update took, following [Restore](#restore).

### Signature verification, mirrors and credentials

- **Verified by default.** Before every update the chart is verified with cosign against the
  Vista Security release signing identity. A chart that does not verify blocks the update.
- **Air-gapped mirrors that cannot re-sign.** If your mirror copies the chart without its
  signature, set `maintenance.updates.skipSignatureVerify=true`. Pre-flight then shows
  *Chart signature* as a **warning**, not a pass, the update's verify step is recorded as
  skipped by configuration, and the chart is installed unverified. Turn this on only when you
  trust the mirror's contents; prefer mirroring with signatures intact.
- **Mirrors without TLS.** `maintenance.updates.plainHttp=true` pulls the chart over HTTP.
- **Mirrors signed by your own CA.** If the registry that holds the chart presents a
  certificate from a private CA (an internal Harbor, an air-gapped mirror), the update check
  reports `x509: certificate signed by unknown authority` and the update's verify and upgrade
  steps fail the same way. Give maintenance-service the CA the way monitoring-service takes
  one for its synthetic checks: mount the PEM from a Secret and point
  `EXTRA_TRUSTED_CA_PATH` at it. The service adds it to the public trust store (never
  replacing it, so a public registry keeps working), cosign gets it as `SSL_CERT_FILE`, and the
  update Job carries the same env and mount, so `helm upgrade` trusts it too.

  ```yaml
  backends:
    maintenance-service:
      extraEnv:
        - name: EXTRA_TRUSTED_CA_PATH
          value: /app/certs/mirror-ca/ca.crt
      extraVolumes:
        - name: mirror-ca
          secret:
            secretName: mirror-ca        # kubectl create secret generic mirror-ca --from-file=ca.crt=…
      extraVolumeMounts:
        - name: mirror-ca
          mountPath: /app/certs/mirror-ca
          readOnly: true
  ```

  A missing or unreadable file is logged at start-up and the service runs with the public
  trust store, as it does without the variable.
- **Private registries.** The registry credential is the first `image.pullSecrets` entry. It
  is never written to the run log.

### Limits

The updater runs under its own namespace-scoped service account and cannot grant itself new
permissions. Kubernetes refuses to let an account apply a Role that gives out permissions the
account does not hold. So if a release's notes say the **maintenance updater's role changed**,
that one update cannot be applied from the console: it fails at the upgrade step and offers a
rollback. Apply it once from the command line as an administrator, using the
[manual procedure](#updating-by-hand) below. The console update works again from then on.

### Installs managed outside Helm

If a GitOps controller (Argo CD or Flux) manages the platform, or it was applied some
other way than `helm install`, About & Updates says so ("Managed by GitOps" or "Not
installed with Helm") and the Update button is off. The console cannot update it: the
controller would undo the change on its next sync. Update it from your values repository,
changing the chart version there, using the notes in the
[production checklist](./deployment/production-checklist.md#gitops-argo-cd--flux). The
update check and the banner still work, and so do backups.

### Updating by hand

The manual Helm procedure is unchanged and always works; the console automates it. It is
the way to update a GitOps install and the fallback if the console is unavailable. See "Run it" in `INSTALL.md` and
[Upgrading](./deployment/production-checklist.md#upgrading) in the production checklist.
Back up first, either way.

---

## Permissions

| What | Permission |
|---|---|
| See running versions, the update status, the backup list and run history | `platform.health` |
| Check for updates now, create / download / delete a backup, run an update, roll back | `platform.maintenance` |

`platform.maintenance` is separate on purpose, so an operator who may watch the
dashboards cannot also download a copy of the database or rewrite the cluster. The
built-in Platform Administrator role has it. To give it to another platform role, see
[Staff & Access](./platform-admin-guide.md#staff--access) in the Platform Administrator
Guide. Every write action, including each download, is recorded in the activity trail.

---

## Turning it off

Set `maintenance.enabled=false` in your chart values and run a normal `helm upgrade`.
That removes the maintenance service, its service accounts and permissions, and the
backups volume, and the console hides the Maintenance section. Nothing else changes.
Download the backups you want to keep first: with the maintenance component off, the
chart no longer manages the backups volume.

To keep the page but stop the outbound registry call, set only
`maintenance.updateCheck.enabled=false`.

The service holds the only credential in the platform that can talk to the Kubernetes
API, and it is limited to the platform's own namespace: no cluster-wide role is created.
You can see the exact permissions in `charts/vistaplatform/templates/maintenance/`.

## See also

- [Platform Administrator Guide](./platform-admin-guide.md)
- [Production Checklist](./deployment/production-checklist.md)
- [Releases & Versioning](./releases.md)
- [Service-mesh mTLS](./security/service-mesh-mtls.md)
