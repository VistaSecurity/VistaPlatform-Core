# Quick Start

Go from a freshly installed Vista Platform to an inventory full of real
data: the certificates, keys, cipher suites and algorithms that your connected
discovery sources can see, scored for risk and for post-quantum exposure.

**About 30 minutes**, most of it spent waiting for discovery to run. You don't
need to do every step. Each of **sensors**, **devices** and **cloud accounts** is
a separate way to feed the same inventory, and the more of them you connect, the
more you'll see. Do one for a first look, or all three. What you find depends on
what each source can reach: a sensor sees the traffic on the network it's
listening to, a device shows only what it's configured with, and a cloud
integration covers only the accounts and regions you connect. Nothing here is a
guarantee that everything is found, and an empty result means nothing was found,
not that nothing is there.

> **Only point Vista Platform at systems you own or are authorized to
> assess.** The three sources behave differently. A sensor mostly **listens**:
> it observes traffic passively. **Active discovery** is separate. A scan you
> start, and the platform's automatic scans of your own private ranges, connect to
> hosts and probe them, and a sensor can make narrow connections of its own to
> read a certificate it couldn't see. Device and cloud steps **log in** to real
> infrastructure with the credentials you give them. The platform records *how*
> things are configured (which algorithms, which certificates), never the key
> material itself.

## Before you start

- **A running platform.** If you haven't installed it yet, start with the
  [install guide](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md).
  You need the address of the web UI: `http://localhost:3000` on a laptop
  install, or your own hostname on Kubernetes.
- **For a sensor:** a Linux, Windows or macOS machine that can reach the
  platform, ideally one that sees real network traffic (more on that below).
- **For a device:** the management address and a login for a firewall or load
  balancer you're allowed to query: F5, Palo Alto, Cisco, Fortinet or UniFi.
- **For a cloud account:** read-only credentials for an AWS account, Azure
  subscription or GCP project.

## 1. Sign in for the first time

1. Open the web UI and click **Create an account**.
2. Enter your work email, name, an **organization** name and a password (at
   least 8 characters), accept the terms if they're shown, and click
   **Create account**.
3. The next screen says *Check your email*. If your platform has mail
   configured, click the link in the message. If it doesn't (the default for a
   fresh install), there's nothing to verify: click **Continue to sign-in**.
4. Sign in. You land on the **Dashboard**.

That first account becomes the **administrator** of your new organization, and
it also closes self-service sign-up, so everyone else you add comes in by
invitation (**Settings → Members**).

The left rail shows the five sections you'll use: **Dashboard**, **Discovery**,
**Inventory**, **Risk & Compliance** and **Remediation**. Settings and your
profile are in the menu at the bottom left, along with a **Getting Started**
checklist that tracks the first steps.

The Dashboard will be empty. That's expected: nothing has been discovered yet.

> **Two consoles, two sets of accounts.** The web UI you just signed in to is
> for your organization. A separate **admin console** (port `3006` on a laptop
> install) is for whoever operates the platform itself. You don't need it for
> this guide.

## 2. Tell the platform about your network

Go to **Settings → Infrastructure → Network Segments** and click **New
segment**. Give it a name, choose **CIDR** as the type, enter the range your
sensor or devices live in (for example `10.0.1.0/24`), set **Network type** to
`private`, and click **Create segment**.

This takes a minute and it matters for two reasons. A segment is how you tell the
platform a range is yours, so it can scan hosts there on its own, and it's how
the platform decides how new discoveries are approved.

**Decide how discoveries get approved.** New assets land in a review queue
(**Discovery → Approvals**) and **stay out of Inventory until someone accepts
them**. That's by design, and it's the reason a first-time user sees "discovery
is running but Inventory is empty". You have two options:

- **Accept them by hand** (step 6). Best when you want to see what's there
  before it counts.
- **Auto-approve** them. Turn on **Auto-approve discoveries** on the segment, and
  anything found inside it skips the queue. Good for a lab or trial network; see
  [Asset Approval](./features/asset-approval.md) before using it on production.

## 3. Add a sensor

A **sensor** is a small program you run inside your network. It listens to
traffic and records the TLS, SSH, SMB and industrial-protocol handshakes it sees.
Listening is passive: it doesn't scan hosts. (Occasionally it makes a narrow
connection to a server of yours to read a certificate that the encrypted
handshake hid.) This is how the platform finds cryptography you didn't know about.

### Register it

1. Go to **Discovery → Sensors & Agents** and click **Register sensor or
   agent**.
2. Leave **Registration type** on **Network sensor**.
3. Enter a **name** (for example `office-sensor-1`) and the **IP address** of the
   machine you'll install it on. Tags and description are optional.
4. Click **Register sensor**.

The confirmation screen gives you a single-use **registration code** (valid for
an hour by default), a **Download** link, and a ready-to-paste **installation command** for
Linux and for Windows. **Use that command.** It already contains your platform's
address and the right code, and it downloads the binary and installer that match
your platform's version.

> **Open the web UI by an address the sensor machine can reach.** The install
> command carries whatever address is in your browser's address bar. If you're
> browsing `localhost`, the sensor machine can't use it. Use the machine's
> hostname or IP address instead.

### Download it

The command above fetches everything for you. If you'd rather download by hand,
or the machine is offline, every release publishes the binaries below on the
[latest release page](https://github.com/VistaSecurity/VistaPlatform-Core/releases/latest).
Pick the one for your machine.

| OS | Architecture | Sensor file | Device agent file |
|---|---|---|---|
| Linux | x86_64 | `crypto-sensor-linux-amd64-<version>` | `device-agent-linux-amd64-<version>` |
| Linux | ARM64 | `crypto-sensor-linux-arm64-<version>` | `device-agent-linux-arm64-<version>` |
| macOS | Intel | `crypto-sensor-darwin-amd64-<version>` | `device-agent-darwin-amd64-<version>` |
| macOS | Apple Silicon | `crypto-sensor-darwin-arm64-<version>` | `device-agent-darwin-arm64-<version>` |
| Windows | x86_64 | `crypto-sensor-windows-amd64-<version>.exe` | `device-agent-windows-amd64-<version>.exe` |
| Windows | x86 (32-bit) | `crypto-sensor-windows-386-<version>.exe` | not offered |

`crypto-sensor-*` is the sensor. That's a historical file name, not a different
product. Use the release that matches your platform's version (profile menu →
**About** shows it) and take the installer script from the same release. Mixing
versions is the most common install failure. Release pages also carry signed
checksums; see [Downloads](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#downloads)
for how to verify them.

The sensor needs a packet-capture library on the machine: `apt install
libpcap0.8` on Debian and Ubuntu, `dnf install libpcap` on RHEL and Fedora,
nothing on macOS, and [Npcap](https://npcap.com/) on Windows.

### Where to put it

A sensor only sees traffic that passes the network card it's listening on.
Plugged into a **mirror or SPAN port** on a switch, it sees that whole segment.
On a single server it sees that server's own connections, which is still enough
for a first look. In the sensor's **Control** tab you choose which network
interfaces it monitors.

### Check that it connected

Stay on the confirmation screen: its status badge updates live from *Not
connected* to *Connected*. If your platform uses a private certificate authority,
the installer shows you the CA it found and asks you to trust it. Compare the
fingerprint it prints against the one shown beneath the registration code before
you say yes; that comparison is the whole security check.

Click the sensor's row in **Sensors & Agents** and open **Discoveries** to watch
what it finds. A busy segment shows results within minutes. A quiet one takes
longer, because a passive sensor can only report what happens on the wire.

> **Want data right now, with nothing to install?** Go to **Discovery → Command
> Center → Discover assets**, enter a subnet or a few addresses you own, and run
> it. This is an **active** scan, unlike a passive sensor: the platform sensor
> connects to each address, performs a TLS or SSH handshake and records what it
> offers. It can reach whatever the platform itself can reach, so only enter
> addresses you're authorized to scan.

Full detail: [Sensor Registration & Management](./features/SENSOR_REGISTRATION.md).

## 4. Add a device

A sensor learns from traffic. A **device** gives you the other half: the platform
logs in to a firewall or load balancer and reads its cryptographic configuration
directly, including settings that never show up on the wire such as VPN
policies, SSL profiles and the certificate store.

1. Go to **Discovery → Devices** and click **Add device**.
2. Choose the **Device type**: F5, Palo Alto, Cisco, Fortinet or UniFi.
3. Enter the **Management URL** (for Cisco, the SSH address), the **Username** and
   the **Password**. Use the least-privileged account that can read the
   configuration.
4. If the device has a self-signed management certificate, tick **Skip TLS
   verification**.
5. Click **Add device**.

The platform connects, reads the device's identity (model, serial number,
firmware) and fills in the rest for you. If it can't connect, nothing is created
and the message tells you why: wrong credentials, an untrusted certificate, or an
address it can't reach. A device that's already in your inventory, because a
sensor saw it, is matched and gets the management details attached rather than
being duplicated.

Then click **Interrogate** on the device's row. Open **Discovery → Discovery
Jobs** to follow the job; when it completes, the device's certificates,
protocols and cipher settings are in your inventory.

**If the platform can't reach the device** (common when the platform runs in a
cloud or another site and the device sits on a private network), run a **device
interrogation agent** next to it instead. Register one the same way as a sensor,
choosing **Device interrogation agent** as the registration type, then use the
`device-agent-*` file from the table above and the enrollment steps on the
confirmation screen. The agent only makes outbound connections and picks up
interrogation jobs from the platform. See
[Device Interrogation](./features/device-interrogation.md) and the
[agent deployment guide](./operate/deployment/device-agent-deployment.md).

## 5. Connect a cloud account

Cloud discovery reads your provider's management APIs with read-only credentials.
Nothing is installed in your cloud and no traffic is mirrored. It finds load
balancers, API gateways and CDN distributions (including the certificates they
serve), your key-management keys, and the at-rest encryption settings on storage
and databases, and it inventories your compute and networks alongside them.

1. Go to **Discovery → Cloud** and click **Connect integration**.
2. Choose the provider and give the integration a name:

   | Provider | What you enter |
   |---|---|
   | **AWS** | An access key ID and secret, *or* a **Role ARN** to assume (avoids a long-lived key; add an External ID) |
   | **Azure** | Directory (tenant) ID, Application (client) ID, client secret and subscription ID |
   | **GCP** | Project ID and a service account JSON key |

3. Click the plug icon on the new row (**Test connection**). A green result means
   discovery will be able to authenticate.
4. Click the play icon (**Run discovery now**), tick the resource types you want
   (all are selected by default) and, for AWS, the regions. Start with one or two
   regions.

Credentials are encrypted at rest and never shown again. The permissions the
account needs are listed in the provider guides:
[AWS](./features/aws-cloud-discovery.md#iam-permissions-required),
[Azure](./features/azure-cloud-discovery.md) and
[GCP](./features/gcp-cloud-discovery.md). Give it only what those pages list.

Open the run from **Discovery → Discovery Jobs** to see, per resource type,
whether it was read, found nothing, or couldn't be read. A resource type that
couldn't be read shows the provider's own error, such as an access-denied that
needs an IAM change.

## 6. Approve what was found

Open **Discovery → Approvals**. Everything the sensor, devices and cloud runs
found is waiting here, unless you turned on auto-approve for its segment in
step 2. Review the list and click **Accept all** (or accept rows one by one).

This is the step that brings the data to life. A discovered asset's certificates
and cryptographic configurations are held back until you accept it, then
appear in Inventory, risk scoring and compliance. Accepting is also what makes
the rest of this page worth looking at.

Cloud resources won't be auto-approved by a segment unless you ticked **Cloud
discoveries** on it, so expect to accept those here the first time.

## 7. See what you've got

Now the payoff. Each of these is a click or two away, and every number you see
links to the exact list it counted.

| Go to | What you'll see |
|---|---|
| **Dashboard → Overview** | The headline: what share of your assets sit on high-risk cryptography, how many are waiting for review or gone stale, and the estate broken down by type. |
| **Inventory → Certificates** | Every certificate found, with issuer, key size and expiry, sorted so the ones closest to expiring are at the top. |
| **Inventory → TLS** | Every TLS configuration. Look for old protocol versions (TLS 1.0 and 1.1) and weak cipher suites. |
| **Inventory → Keys** and **Configuration** | Key algorithms and sizes, and the full cryptographic configuration of each service. |
| **Inventory → Map** | The network around any asset: what it connects to and what breaks if it changes, plus a topology view of the whole estate. |
| **Dashboard → PQC** | Which assets use algorithms a quantum computer will break, and the migration worklist for replacing them. |
| **Risk & Compliance → Posture** | Your score against the free frameworks: security best practices, post-quantum readiness, certificate hygiene and more. Best Practices is always on; activate the others here. |
| **Risk & Compliance → Findings** | Each problem found, with severity. |
| **Risk & Compliance → Bills of Materials** | Click **Generate** to produce a frozen, content-hashed CycloneDX cryptographic bill of materials: the document you hand an auditor. |

If you only have time for two: open **Inventory → Certificates** and look at
the top of the list, then open **Dashboard → PQC**. Most people find something they didn't
know was there within the first few minutes.

## If something looks wrong

| You see | Likely cause |
|---|---|
| Discovery ran but Inventory is empty | The assets are waiting in **Discovery → Approvals** (step 6). |
| The sensor never reaches *Connected* | The sensor machine can't reach the platform address in the install command, or the registration code expired or was already used. Register again to get a new code. |
| The sensor is connected but finds nothing | It's listening on an interface that doesn't carry the traffic. Open its **Control** tab and use **Detect** to choose the right network interface. |
| **Add device** fails | The message names the reason: credentials, certificate trust or reachability. Tick **Skip TLS verification** for a self-signed management certificate. |
| A cloud run is partly collected | A resource type was denied. The job's detail shows the provider's error and which permission to add. |

## Where next

- [Getting Started checklist](./features/getting-started.md): the in-product
  version of these steps.
- [Inventory & Lenses](./features/inventory-and-lenses.md) and
  [The Dashboard](./features/dashboard.md): reading what you've collected.
- [Discovery](./features/discovery.md) and
  [Automatic Active Scanning](./features/active-scanning.md): what the platform
  scans on its own, and how to control it.
- [CBOM Artifacts](./cbom/cbom-artifacts.md): turning the inventory into evidence.
- [Tenant User Guide](./guides/tenant-user-guide.md): the whole console, section
  by section.
