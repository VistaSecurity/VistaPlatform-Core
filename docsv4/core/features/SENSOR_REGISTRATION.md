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
sensor has a segment and an "assets found" count; an agent has a profile, an
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
   a **description**.
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

The list hides itself entirely when there is nothing pending. While a
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

The installer places the binary, drives the certificate enrollment described
below, and registers it as a service.

**Verifying what you downloaded.** Every release publishes a `SHA256SUMS` file
alongside the binaries, signed with cosign (keyless — there is no key to trust):

```bash
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp 'https://github.com/VistaSecurity/VistaPlatform-Core/.github/workflows/release-core.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS
```

The most common install failure is mixing a binary and an installer script from
two different releases. Use the pair from one release.

## What a sensor's detail panel shows

Click any sensor row to open its panel. It has four tabs.

### Overview

Status, last heartbeat (which becomes *last seen* once the sensor goes offline),
reporting interval, version, IP address, every address the host holds when there
is more than one, whether the deployment is air-gapped, uptime, the monitored
interfaces, the description and the tags.

**The certificate lives here too**, as a card at the bottom: its state (Active /
Expiring soon / Expired / Revoked), days remaining, serial, issue and expiry
dates, a **Download** button for the certificate itself, and — with **Full sensor
management** (`sensors.manage`) — **Revoke**, which requires a reason and takes effect
immediately. There is no separate certificates tab.

### Discoveries

The most recent things this sensor found: protocol, destination, port,
confidence and timestamp.

### Health

Current metrics — uptime, memory, packets captured, discoveries in the last
interval, and discoveries in total — with a history table underneath over 1 hour,
24 hours or 7 days.

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

### Control

Configuration and commands, for users with the **Update sensors** permission
(`sensors.update`).

**Network interfaces.** Tick the interfaces the sensor should monitor and click
**Save NICs** to send the change — nothing is queued until you do. **Detect**
asks the sensor to report what the host actually has; an interface you typed in
by hand that the host has not reported is flagged *not detected on host* rather
than silently accepted.

**Configuration.** Air-gapped or connected, description, tags.

**Reporting interval.** See [below](#changing-a-sensors-reporting-interval).

**Commands.** Queue an action for the sensor to pick up on its next check-in:
restart, clear cache, update interfaces, list interfaces, export logs, update
config. Command types the sensor does not genuinely act on are not offered.

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
| Register a sensor or agent, delete a pending registration | `sensors.create` / `sensors.delete` |
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
2. Open the **Control** tab → **Reporting interval**.
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
| `GET` / `PUT` | `/api/v1/sensor-manager/admin/settings` | Registration-code expiry, pending cap, address validation |

The registration response returns the signed certificate and the platform CA.
It never contains a private key — that stays on the sensor's host and is never
transmitted.

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
**Control → Detect** to see what the host actually has.

## Related

- [Host Inventory](./host-inventory.md) — what an agent can collect about a host
- [Discovery](./discovery.md) — what sensors find, and where it goes
- [Device Interrogation](./device-interrogation.md) — what agents do with a job
- [Device Agent Deployment](../operate/deployment/device-agent-deployment.md) — installing and running the agent
- [PCAP Ingestion](./pcap-ingestion.md) — inventorying a segment that cannot host a sensor
