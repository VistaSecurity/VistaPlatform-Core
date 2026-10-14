# bundle-decrypt

Opens an encrypted Vista Platform backup bundle — the `.enc` file a platform
admin downloads from **Maintenance → Backups** when the backup included the
encryption keys and install secrets — and writes the tar inside it. It needs
only the file and the passphrase chosen when the backup was created; the
platform does not have to be running, which is the point during a restore.

## Build

From the repository root (Go 1.26, the version `go.work` pins):

    cd services/maintenance-service
    go build -o bundle-decrypt ./cmd/bundle-decrypt

## Use

    ./bundle-decrypt -in vista-platform-backup-20261014-031200-4.6.0.enc -out bundle.tar

The passphrase is read from `VISTA_BACKUP_PASSPHRASE` when set, otherwise from
the terminal (no echo), otherwise from the first line of standard input. It is
never a command-line flag, so it does not land in shell history or `ps`.

The tar contains:

| File | What it is |
|---|---|
| `database.dump` | `pg_dump -Fc` of the platform database — restore with `pg_restore` |
| `manifest.json` | versions, schema hash, edition, install id, contents, `pg_dump` version |
| `secrets.yaml` | the chart's Secrets as a Kubernetes `List` — `kubectl apply -f` into the new namespace **before** installing the chart; includes the CBOM artifact signing key when `manifest.json` `contents.cbom_signing_key` is true, so restored CBOM artifacts still verify |

`secrets.yaml` holds the encryption master key, the JWT signing key, the
install identity and (when present) the CBOM signing key. Treat the decrypted tar as you would the live cluster's
Secrets, and delete it once the restore is done.

The output is written to `<out>.partial` and renamed only once the whole bundle
has authenticated: a wrong passphrase, a truncated download or a modified file
fails with an error and leaves no output behind.

## Format

AES-256-GCM in 1 MiB chunks under a key derived from the passphrase with
Argon2id (parameters and salt in the file header); the last chunk is marked
final, so a file cut short cannot decrypt to a shorter bundle. The format is
specified in `internal/bundlecrypt/bundlecrypt.go`.

The full restore procedure is in the platform maintenance docs.
