# Sensor & Agent Registration

> **Looking for the binary?** The canonical download instructions — the
> OS/arch table, the GitHub Releases link, and how to verify what you
> downloaded — live in
> [Downloads in INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#downloads).
> This page repeats the sensor-specific parts of that inline for convenience.

Everything on this page happens under **Discovery → Sensors & Agents**.

## The two things you can register

| | **Network sensor** | **Device interrogation agent** |
|---|---|---|
| What it does | Watches traffic on the interfaces you give it, passively | Waits for work and logs in to devices to ask them questions |
| Deployed on | A host with a mirror / SPAN port onto the segment you care about | Any host that can reach the devices you want interrogated |
| Reports | Cryptographic sessions, host observations, health | Job results, and optionally an inventory of its own host |

Both are registered from the same button and appear on the same page, in two
tables — because a sensor row and an agent row answer different questions. A
sensor has a network and an "assets found" count; an agent has a profile, an
address inventory and a job history.

### Platform sensors

Every organization also has **platform-managed** rows it did not deploy: a
platform discovery sensor and a platform interrogation agent. They are your
workspace's handle to shared in-cluster services, and they carry your results
into your inventory.

- They show a lock instead of a delete button, and the platform refuses a delete
  request whether or not the button was shown. Removing one would not stop the
  shared service — it would quietly cut your interrogation and scheduled-scan
  results off from your inventory.
- They report no health, no commands, no configuration and no certificate, so
  their detail panel shows only **Overview** and **Discoveries**.
- Discovery counts and activity are still yours alone; the row is per-workspace
  even though the service behind it is shared.

## Registering

1. Go to **Discovery → Sensors & Agents** and click **Register sensor or
   agent**. (You need the **Create sensors** permission; without it the button
   is not shown.)
2. Pick the **registration type** — *Network sensor* or *Device interrogation
   agent*.
3. Fill in the few fields there are: a **name** (an *agent label* for an agent),
   the **IP address** the thing will register from, and optionally **tags** and
   a **description**. The tags `system` and `platform` are reserved for the
   platform's own sensors and are dropped if you enter them, here and on the
   sensor's configuration later.
4. Click **Register sensor** / **Register agent**.

The confirmation screen gives you:

- the **registration code**, with a copy button;
- the **installation command** for Linux and for Windows, pre-filled with the
  code, the address and the name (for an agent, the equivalent **enrollment
  steps**);
- the **platform CA fingerprint**, when your platform needs one — see
  [Trusting a privately-signed platform](#trusting-a-privately-signed-platform).

Registration codes are **single-use** and **time-limited** (60 minutes by
default). A code that has already enrolled something is refused permanently.

### Pending registrations

Anything registered but not yet connected appears in a **Pending registrations**
list at the bottom of the page, with the name, address, profile and code. Each
row offers:

- **Command** (or **Enroll**, for an agent) — reopens the install command or the
  enrollment steps;
- **delete** — drops the pending registration if you no longer need it.

The list hides itself entirely when there is nothing pending, and for anyone
without `sensors.create`: a pending registration carries the registration code,
which is all a sensor needs to enrol, so only people who can mint a code can see
the outstanding ones. While a
registration is open, its status reads as one of:

| Status | Meaning |
|---|---|
| Not connected | Nothing has checked in with this code yet |
| Registered | It enrolled, and the first data has not arrived |
| Connected | It is checking in and sending data |
| Expired | The code timed out — mint a new one |

## Installing

Installing needs two things together: the platform-specific **binary** and the
matching installer script (`install-sensor.sh` on Linux and macOS,
`install-sensor.ps1` on Windows).

**Getting the binary.** Either download the `crypto-sensor-<os>-<arch>-<version>`
asset — for example `crypto-sensor-linux-amd64-v1.0.0` — from the GitHub Release
matching your platform version, or build it from a source checkout
(`make build-sensor` for the current platform, `make sensor-all-platforms` for
every supported target). The platform does **not** serve sensor binaries over
HTTP: no service anywhere has a download endpoint, for tenants or for platform
administrators.

Supported targets are Linux (x86_64, ARM64), Windows (x86_64, 386) and macOS
(x86_64, Apple Silicon). The installer script for a release is published
alongside the binaries.

**Running the installer.** The confirmation screen and the pending-registration
row both build the exact command:

```bash
sudo ./install-sensor.sh --url https://<your-platform-host> --key <registration-code> --ip 10.0.0.50 --name sensor-dc01
```

```powershell
.\install-sensor.ps1 -Url https://<your-platform-host> -Key <registration-code> -IP 10.0.0.50 -Name sensor-dc01
```

A `--key` on the command line is visible to other users in the process list. On
Linux and macOS, set `VISTA_REGISTRATION_KEY` in the environment or pipe the key
to `install-sensor.sh --key-stdin` instead. The installer shows only the last four
characters of the key in its output.

A sensor that cannot start because only a person can fix it (the control plane
rejected the registration key, or the config file cannot be parsed) exits with
status `78` (`EX_CONFIG`). The Linux systemd unit sets
`RestartPreventExitStatus=78`, so it stops instead of retrying every 10 seconds;
generate a new key and re-run the installer. The Windows installer already
disables the service after a rejected key; neither Windows services nor launchd
can exclude an exit status from restart.

The installer checks the packet-capture runtime (libpcap on Linux, Npcap on
Windows), installs the binary as a service, and starts it. The sensor then
enrolls itself with the registration code — the certificate enrollment
described below — and the installer waits until it has, printing the sensor's
ID and version. If the platform rejects the code (expired, invalid or already
used), the installer stops the service and says so. Re-running the same command
on a host that code already enrolled keeps the sensor's identity and replaces
only the binary, which is how to upgrade it in place.

On Windows the sensor runs as the `VistaSensor` service. It writes its log to
`data\logs\sensor.log` under the install directory (by default
`C:\Program Files\VistaSensor\data\logs\sensor.log`, rotated to `sensor.log.1`
at 10 MB), and records start and stop events in the Application event log under
the source `VistaSensor`. Follow the log with
`Get-Content -Tail 50 -Wait "$env:ProgramFiles\VistaSensor\data\logs\sensor.log"`.
On Linux the sensor logs to the systemd journal (`journalctl -u crypto-sensor`).

**Verifying what you downloaded.** Every release publishes a `SHA256SUMS` file
alongside the binaries, signed with cosign (keyless — there is no key to trust):

```bash
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp '^https://github\.com/VistaSecurity/VistaPlatform-Core/\.github/workflows/release-core\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS
```

The most common install failure is mixing a binary and an installer script from
two different releases. Use the pair from one release.

## What a sensor's or agent's detail panel shows

Click any sensor or discovery agent row to open its panel. Both use the same
tabs in the same order — **Overview · Discoveries · Health · Jobs · Logs ·
Settings** — and leave out the ones a device cannot support rather than showing
them empty:

| Tab | Sensor | Discovery agent |
|---|---|---|
| Overview | ✓ | ✓ |
| Discoveries | ✓ | — its work arrives as jobs |
| Health | ✓ | ✓ |
| Jobs | ✓ | ✓ |
| Logs | ✓ | ✓ |
| Settings | ✓ | ✓ |

A platform sensor shows only Overview and Discoveries: it runs in the cluster
and reports no health, jobs or settings.

### Overview

Status, last heartbeat (which becomes *last seen* once the sensor goes offline),
reporting interval, version, IP address, every address the host holds when there
is more than one, whether the deployment is air-gapped, uptime, the monitored
interfaces, the description and the tags.

**Host**, once it appears: a link to the Inventory asset for the machine the
sensor itself runs on. The sensor reports its own hostname and interfaces so
that machine is a named, classed asset instead of an anonymous entry — and so
an automatic active scan never targets the sensor's own host. The row is
absent until the sensor's first self-report resolves (or on a sensor build old
enough to predate the feature).

**The certificate lives here too**, as a card at the bottom: its state (Active /
Expiring soon / Expired / Revoked), days remaining, serial, issue and expiry
dates, a **Download** button for the certificate itself, and — with **Full sensor
management** (`sensors.manage`) — **Revoke**, which requires a reason and takes effect
immediately. There is no separate certificates tab.

### Discoveries

The most recent things this sensor found: protocol, destination, port,
confidence and timestamp.

### Health

Both kinds open with the same **Connection** block: online or offline, last
heartbeat, the version it runs, and whether it has taken the settings you gave
it (*Applied*, *Pending*, *Awaiting restart*, *Failed*, *Not reporting*).

A **sensor** then shows current metrics — uptime, memory, packets captured,
discoveries in the last interval, and discoveries in total — with a history
table underneath over 1 hour, 24 hours or 7 days.

A **discovery agent** reports no process metrics, so its Health tab shows what
the platform sees it do: jobs run in all, when it last ran one, how many of its
recent jobs completed or failed, and when it last inventoried its own host.

Two metrics that exist in the data are deliberately **not** shown here: a CPU
figure that is an estimate rather than a measurement, and an error count that is
always zero. A number that looks like an answer and is not is worse than a blank.

#### Host observations

When the sensor is reporting them, this tab also shows what it has seen of hosts
announcing themselves on the wire — devices that never open a connection the
crypto pipeline watches. Three tiles:

| Tile | What it means |
|---|---|
| **Hosts seen** | Devices observed over the selected range |
| **Shed** | Observations the sensor dropped rather than sending |
| **Accumulating now** | Subjects currently being gathered up, waiting to be sent |

**A non-zero shed count is actionable.** It means the segment is busier than the
sensor is sized for, and devices on it may be missing from your inventory
entirely. Give the sensor more resources, or narrow the interfaces it monitors.

Two honesty notes worth understanding:

- **The block is absent, not zeroed, when the sensor is not reporting these
  counters** — an older build, or the feature switched off. "Not running" and
  "running and seeing nothing" must not look the same.
- **The figures are a difference across the range**, because the sensor's
  underlying counters only ever count up. If the sensor restarted inside the
  range, the range's own figure is not knowable, so the tiles say *since
  restart* and show the running total instead of quietly under-reporting.

Each observation becomes a pending asset in **Discovery → Approvals**. What one
looks like there — and why it can be so sparse — is covered in
[Discovery](./discovery.md#passive-host-observation).

### Jobs

The last 10 things the device was asked to do, newest first, one line each with
its status (*Queued*, *Delivered*, *Running*, *Completed*, *Failed*). Click a
line to see its detail; click it again to close it.

- **On a sensor** a job is a command or a discovery job handed to it. The detail
  shows when it was sent, delivered, acknowledged and finished, the payload sent
  and the sensor's reply. With **Update sensors** you can also **Send a
  command**: clear cache, detect interfaces, update interfaces or update
  configuration. Command types the sensor does not genuinely act on are not
  offered; restart and log export have their own controls.
- **On a discovery agent** a job is an interrogation assigned to it. The detail
  shows the target asset, timing, duration, assets found, any error, and the
  job's results. Jobs reach an agent from **Managed Devices** and the asset scan
  actions; every job in the organization is listed in **Discovery Jobs**.

### Logs

**Fetch logs** asks the device for its most recent 100, 200 or 500 log lines.
It replies at its next check-in and the lines appear here as text. Asking needs
**Update sensors**; reading what came back needs only **View sensors**.

Credentials that appear in a line — a password in a URL, an `Authorization`
header, a `"password": …` pair — are masked before the line is shown. A
discovery agent masks them before the lines leave its host, and the platform
masks them again.

A discovery agent's lines are kept for a day, and a request it has not collected
expires after an hour. An agent from a release before this one cannot send its
logs, and its Logs tab says so; upgrade it to use the tab.

### Settings

The managed settings described in
[Agent and sensor settings](./agent-and-sensor-settings.md), their change
history, and **Restart**. Restart warns, before you confirm, that a device
launched by hand rather than run by a service manager will stop instead of
restarting. A sensor's restart needs **Update sensors**; an agent's needs **Full
sensor management** (`sensors.manage`).

A sensor's Settings tab also holds its own record, for users with **Update
sensors** (`sensors.update`):

**Network interfaces.** Tick the interfaces the sensor should monitor and click
**Save interfaces** to send the change — nothing is queued until you do. **Detect**
asks the sensor to report what the host actually has; an interface you typed in
by hand that the host has not reported is flagged *not detected on host* rather
than silently accepted.

**Configuration.** Air-gapped or connected, description, tags.

**Reporting interval.** See [below](#changing-a-sensors-reporting-interval).

## Host inventory (agents)

A device interrogation agent can also inventory a **host** — its own, on a
timer, or another over SSH as a queued job. It is off by default. An agent that
has reported one shows a *"Last host inventory: 2h ago — 412 packages, 18
listeners"* line on its row here.

See [Host Inventory](./host-inventory.md) for what is collected, how to turn it
on, and where the result lands.

## Certificates and trust

### How a sensor gets its certificate

The sensor generates its private key **on its own host** and sends only a
certificate signing request. The platform signs it and returns the certificate;
the private key never crosses the network and the platform never holds it.

- Each organization has its own long-lived certificate authority.
- Sensors rotate automatically when their certificate is within 30 days of
  expiry.
- Revoking a certificate takes effect immediately; the sensor must re-register
  to get a new one.
- All sensor-to-platform communication is mutually authenticated.

### What a sensor keeps after enrolling

The registration code is single-use and is **not kept** once the sensor is
enrolled. At enrollment the platform issues the sensor a random **sensor
secret**, once, alongside its certificate. The platform keeps only an encrypted
copy and cannot show it again.

- The sensor keeps the secret in `<data path>/certs/agent-secret.json`
  (owner-only), written together with its certificate so a rotation replaces
  both or neither.
- Its config file no longer contains `registrationKey`. It records
  `registrationKeySha256`, a fingerprint, in its place, so re-running the
  installer with the same code is still recognised as "this host is already
  enrolled" and keeps the sensor's identity. The code is removed from the config
  only once the secret is safely on disk; if the platform did not issue a secret
  or the save failed, the code stays where it was.
- Every certificate rotation issues a **new** secret. The one it replaces stays
  valid for **24 hours** (so anything sealed just before the rotation still
  opens) and is then discarded from the file.
- A sensor enrolled before this existed keeps working with no re-enrollment: it
  receives its first secret at its next certificate rotation and drops the
  registration code from its config then. A sensor build that predates the
  feature is never issued a secret.
- A sensor run from environment variables alone (no config file) cannot have the
  code removed from its environment; it still stores the secret next to its
  certificate, and a restart needs the same environment as before.

### Trusting a privately-signed platform

A self-hosted platform commonly serves its edge certificate from an internal CA
that the agent's host does not trust. Registration is itself an HTTPS call, so
without a trust anchor it fails certificate verification before a sensor can
enroll. Agents resolve this the way SSH resolves an unknown host key — an
explicit, one-time decision — and **never** by skipping verification.

**Interactive install.** The interactive installer — which is what running the
sensor or agent with no arguments does on an unconfigured host, and what
`--interactive` forces on a configured one — detects the untrusted certificate
during the connectivity check, then shows the CA the platform presents and asks:

```
⚠️  The platform's certificate is not signed by any CA this host trusts.

    Subject:     CN=Acme Internal Root CA,O=Acme Corp
    Issuer:      CN=Acme Internal Root CA,O=Acme Corp
    Type:        self-signed root CA
    Valid:       2026-08-11 → 2027-08-11
    SHA-256:     43:7c:fc:92:2e:3a:2f:24:1c:53:c4:e2:a8:de:49:64:
                 e3:7e:d7:12:46:ff:6e:98:69:47:bf:ac:72:b8:f0:f6

Trust this CA for this agent? (y/N):
```

Accepting writes the CA into the agent's own data directory and records it in
the agent's configuration. Declining cancels setup; the agent will not connect
to a platform it cannot verify.

The anchor you approve verifies **enrollment** — the connection that matters
most, because it happens before the agent has any other way to know who it is
talking to. It then keeps verifying every connection afterwards.

Registration additionally returns the platform's own CA, and the agent **adds**
it to its trust pool rather than replacing what you approved. Both are kept, and
that is deliberate: the CA you approved is what signs the ordinary endpoint,
while the one returned at registration signs the mutually-authenticated listener
that exists only in some deployments. Which of the two an agent ends up talking
to is a deployment choice, so it carries both and verifies against whichever
applies. The file on disk after enrollment may therefore contain more
certificates than you approved, but never fewer. Verification is never disabled
in either phase.

**Unattended install.** A scripted install cannot answer a prompt, so pass the
expected fingerprint instead:

```bash
crypto-sensor --ca-fingerprint 437cfc922e3a2f241c53c4e2a8de4964e37ed71246ff6e986947bfac72b8f0f6
```

The agent pins the CA only if it hashes to that value, and aborts loudly on a
mismatch. Colons, uppercase, and a `sha256:` prefix are all accepted. With no
fingerprint and no operator to ask, the agent refuses rather than pinning
something nobody approved.

**Where to get the expected fingerprint.** The platform shows it to you when you
mint the registration code: **Discovery → Sensors & Agents → Register sensor or
agent**, on the confirmation screen directly beneath the registration code and
install commands. Copy it, then compare against what the agent prints.

The panel appears only when it is needed. A platform whose certificate is
publicly trusted shows nothing — agents verify it automatically and never
prompt. If the platform cannot inspect its own certificate (no public URL
configured, plain HTTP), the panel says so and points at the manual route:

```bash
openssl s_client -showcerts -connect <platform-host>:443 </dev/null 2>/dev/null | openssl x509 -outform PEM | openssl x509 -noout -fingerprint -sha256
```

**Why the comparison is the whole point.** This is trust-on-first-use: an
attacker positioned at the moment of enrollment could present their own CA and
the prompt would happily offer it for approval. Reading the expected value from
the console — a separate, authenticated session — is what closes that gap. An
approval given without comparing provides no protection at all.

If the agent shows a fingerprint that does not match, stop. Either the CA was
rotated since you last looked, or something is sitting between the agent and the
platform.

**When the platform's certificate is for the wrong hostname.** Before offering
you anything to approve, the agent checks that the certificate the platform
presents is actually valid for the address you pointed it at. If it is not, the
agent refuses and tells you what it found instead:

```
❌ The server at vista.example.com is presenting a certificate for
   a1b2c3d4.traefik.default.

    Its TLS is misconfigured — this is a problem on the platform, not here.
    Trusting the CA behind it would not help: certificate verification
    checks the hostname BEFORE it checks who signed it, so every
    connection would still fail with the same error.

    Common cause: the platform's TLS certificate was never installed, so
    its ingress controller is serving a placeholder.
```

This is not a trust decision you can make differently — no CA you approve can
rescue a name mismatch, because hostname verification runs first. Approving one
anyway would produce an agent that reports a completed security step and then
fails every connection.

The usual cause is the one named: the platform's TLS secret is missing or
misnamed, so its ingress controller falls back to its own self-issued
placeholder. Fix the platform's certificate, then run setup again. The same
refusal applies on the unattended `--ca-fingerprint` path — a correct
fingerprint proves you have the right CA, but says nothing about whether the
server is serving the right certificate.

**When none of this applies.** A platform with a publicly-trusted certificate
verifies against the host's system trust store and the prompt never appears.
Installing the internal CA into the host's own trust store has the same effect.

## Registration security

- **Codes are bound to an address.** A sensor must register from the address the
  code names.
- **Codes are single-use and expire.** Default 60 minutes; the platform-wide
  limits are 5–1440 minutes and a cap on how many registrations may be pending
  at once.
- **The organization comes from the code, not from the request.** A registering
  sensor inherits the organization the code was minted in; nothing it sends can
  change that, and row-level security enforces the isolation underneath.

## Permissions

| Action | Permission |
|---|---|
| Register a sensor or agent, see pending registrations, delete a pending registration | `sensors.create` / `sensors.create` / `sensors.delete` |
| Change monitored interfaces, configuration, reporting interval | `sensors.update` |
| Revoke or regenerate a certificate | `sensors.manage` |
| Delete a sensor | `sensors.delete` |
| Delete a discovery agent | `discovery.manage` |

## Changing a sensor's reporting interval

The **reporting interval** is how often a sensor sends discovered data to the
platform. It is set on the sensor at install time, reported up, and shown on the
sensor's **Overview** tab.

To change it from the console:

1. Go to **Discovery → Sensors & Agents** and click the sensor.
2. Open the **Settings** tab → **Reporting interval**.
3. Pick a value — **30 seconds, 1 / 5 / 15 / 30 minutes, or 1 / 2 / 4 / 8 / 12 /
   24 hours** — and click **Apply**.

The change is **queued as a command** and takes effect the next time the sensor
checks in, so an offline sensor picks it up when it reconnects. Once applied,
the sensor reports the new interval back and the Overview tab updates. The value
is saved on the sensor, so it survives restarts.

**Choosing a value:** shorter intervals surface discoveries faster but generate
more traffic and platform load; longer intervals suit low-change or
bandwidth-constrained environments. For large fleets, standardising on a few
intervals keeps load predictable.

## Scans run from a sensor

A discovery scan described by **scan depth** can run from one of your sensors
(*Run from: Auto* picks the sensor on the target's network, or you name it). The
sensor runs it with the same scan engine as the platform sensor and reports each
host back as soon as it is done — see [Discovery → From one of your
sensors](./discovery.md#scan-depth-ports-pace-and-where-it-runs-api) for what
the scan does and how progress, cancel and Retry behave.

What this means for the sensor and its host:

- **Version.** The sensor tells the platform on every check-in that it can run
  such scans; only a sensor that does is handed one. An older sensor is never
  chosen by *Auto*, and naming it is refused with "upgrade it, or run the scan
  from the platform" — upgrade the sensor binary to run these scans from it.
- **Its own limits.** Whatever a scan names, the sensor never contacts its own
  loopback, link-local (including cloud metadata), multicast or broadcast
  addresses, an address in a range you excluded from probing, or one outside
  your networks as the platform last told it. Such an address is reported as
  *could not be scanned*, with the reason.
- **Traffic.** Besides the scan itself, the sensor sends one small report per
  host finished and a check-in at least once a minute while a scan runs, over
  the same authenticated connection as its heartbeat. A sensor that cannot
  reach the platform for 15 minutes has its scan marked failed; what it had
  reported is kept.
- **One scan at a time.** A sensor runs one scan; up to 8 more wait in its
  queue. Cancelling a waiting scan drops it unstarted.

## API

Registration and management are available over the API for automation.

| Method | Path | What it does |
|---|---|---|
| `POST` | `/api/v1/sensor-manager/sensors/pending` | Mint a registration code |
| `POST` | `/api/v1/sensor-manager/sensors/register` | Enroll, with a certificate signing request |
| `PUT` | `/api/v1/sensor-manager/sensors/{id}/interfaces` | Change monitored interfaces (`add` / `remove`) |
| `PUT` | `/api/v1/sensor-manager/sensors/{id}/config` | Air-gapped flag, description, tags, reporting interval |
| `POST` | `/api/v1/sensor-manager/sensors/{id}/commands` | Queue a command |
| `GET` | `/api/v1/sensor-manager/sensors/{id}/health` | Latest health metrics |
| `GET` | `/api/v1/sensor-manager/sensors/{id}/certificates` | Certificate status |
| `POST` | `/api/v1/sensor-manager/sensors/{id}/certificates/rotate` | Rotate, with a new signing request |
| `POST` | `/api/v1/sensor-manager/sensors/{id}/certificates/revoke` | Revoke, with a reason |

The registration response returns the signed certificate and the platform CA.
It never contains a private key — that stays on the sensor's host and is never
transmitted. When the request sets `supports_agent_secret: true` it also returns
`agent_secret` and `agent_secret_version`, once; the rotation response does the
same, with a new secret that replaces the old one.

A sensor reports the version it was built as. A binary built from source without
a stamped version reports `dev`; the console shows whatever it reported.

## Troubleshooting

### The sensor is running but nothing appears in the platform

A sensor that could not register can capture traffic but cannot submit any of
it. Check the sensor's log for its startup line — it reports which state it is
in, and repeats the warning every 10 minutes while the problem persists:

```
⚠️  Sensor started UNREGISTERED — it is capturing traffic and can submit none of it.
```

There are two shapes of this, and the log distinguishes them:

- **The platform was unreachable.** The sensor keeps retrying on its own,
  starting 30 seconds out and backing off to a 15-minute ceiling. No restart is
  needed — once the platform is reachable again the sensor registers and logs
  `✅ Registration succeeded on retry`. This is expected when a sensor is
  installed before the platform is ready, or while it restarts.

- **The registration code was rejected.** The sensor refuses to start and says
  so, quoting the platform's own reason:

  ```
  ⛔ Registration was REJECTED by the control plane (HTTP 400):
     {"error":"Registration key has already been used"}
  ```

  Retrying cannot resolve this. Registration codes are single-use, so a code
  that has already enrolled a sensor is refused permanently. Mint a new one
  (**Discovery → Sensors & Agents → Register sensor or agent**), put it in the
  sensor's config, and start it again.

### "Registration key not found"

The code expired or never existed. Mint a new one and re-run the installer.

### "The server … is presenting a certificate for …"

The platform's TLS certificate is not valid for the hostname you pointed the
agent at — most often because its TLS secret is missing and its ingress
controller is serving a self-issued placeholder. Fix the platform's certificate,
then run setup again. Trusting the CA behind the placeholder cannot help; see
[Trusting a privately-signed platform](#trusting-a-privately-signed-platform).

### "Certificate validation failed" / "Certificate has expired"

Check the certificate card on the sensor's **Overview** tab. A sensor rotates
automatically inside 30 days of expiry; one that has been offline long enough to
expire needs to re-register.

### "Certificate has been revoked"

Revocation is final for that certificate. The sensor must re-register to obtain
a new one.

### "Can't find a binary for my platform"

Check the Release's assets for `crypto-sensor-<os>-<arch>-<version>`, or build it
yourself. There is no download endpoint on the platform to look for.

### A sensor shows online but its counts are not moving

Check the **Health** tab's history over 24 hours. Packets captured flat at zero
usually means the monitored interfaces are wrong for where the traffic is — use
**Settings → Detect** to see what the host actually has.

## Related

- [Host Inventory](./host-inventory.md) — what an agent can collect about a host
- [Discovery](./discovery.md) — what sensors find, and where it goes
- [Device Interrogation](./device-interrogation.md) — what agents do with a job
- [Device Agent Deployment](../operate/deployment/device-agent-deployment.md) — installing and running the agent
- [PCAP Ingestion](./pcap-ingestion.md) — inventorying a segment that cannot host a sensor
