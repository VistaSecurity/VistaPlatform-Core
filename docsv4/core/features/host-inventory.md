# Host Inventory

A discovery agent can describe a **host** as well as interrogate a network
device: what operating system it runs, what hardware it is, what software is
installed on it, and what is listening on it. That last one is the point. A
listening socket the machine itself reports is the only evidence that ties a
service to *that machine* rather than to an address it happens to answer on
today — and it finds the loopback-only and firewalled services no network scan
can reach.

Host inventory is **off by default**. Nothing starts collecting because an agent
was upgraded; somebody has to turn it on or queue a job.

## What is collected

| Group | What the host is asked for |
|---|---|
| **Operating system** | Product name, version, kernel or build, host name, fully-qualified name, domain |
| **Hardware** | Vendor, model, serial number, system UUID, firmware version |
| **Interfaces** | Name, MAC address, addresses, whether the interface is up, whether it is virtual |
| **Software** | Installed packages — name, version, vendor, architecture, and the package manager that reported them |
| **Listening sockets** | Transport, bound address, port, and the name of the process that owns it |
| **Certificate stores** | Store path, how many certificates it holds, and per certificate the subject, issuer, SHA-256 fingerprint and expiry |

**Posture, never key material.** Certificate stores are read for *certificates*:
a file that is not a certificate is skipped before it is decoded, and the stored
shape has nowhere for key bytes to sit. A private key found loose in a trust
directory is reported as a **count** and nothing else — which is worth knowing
about on its own. Command output is never stored as a transcript, process
command lines are never read (only the process *name* that owns a socket), and
no process id is kept: a pid identifies a process on one boot of one machine, so
it is meaningless by the time anyone reads it back.

**Every section answers three ways, not two.** Each group above reports *ok*,
*failed* or *unsupported*. A host whose package database could not be read and a
host with no packages are different answers, and the platform keeps them apart —
a failed step contributes nothing at all rather than contributing a zero. That
is also why a collection never marks software "removed" off the back of a failed
package step.

## Two modes

|  | **Local** | **Remote** |
|---|---|---|
| Describes | The machine the agent is installed on | Another machine, reached over SSH |
| Credentials | None — the agent is already there | The target's stored SSH credentials |
| Started by | The agent's own timer | A job you queue against a device |
| Identity | Strongest: the agent's own id, plus the host's serial and MAC addresses | Whatever the host reports — serial, MAC addresses, names |
| Sees loopback sockets and the package database | Yes | Yes, as far as the login account is allowed to |

Both modes run the same commands and parse the same output, so a host described
remotely and a host described locally produce the same record.

### Turning local collection on

**From the console:** Discovery → Sensors & Agents → click the agent → **Settings**
→ turn on **Host inventory enabled** and set **Host inventory interval**. The
agent picks it up at its next check-in; the tab shows whether it has. To turn it
on for every agent at once, use **Agent defaults** on the same page. See
[Agent and sensor settings](./agent-and-sensor-settings.md).

The interval has a **one-hour floor**. A shorter value is raised to the floor,
and the console says so when it does — asking for five minutes walks the whole
package database twelve times an hour, which is not what anyone wants from a
setting they typed once.

**At install time,** before an agent has ever checked in, the same two settings
can be set on the host:

| Setting | Meaning | Default |
|---|---|---|
| `HOST_INVENTORY_ENABLED` | `true` turns the local schedule on | off |
| `HOST_INVENTORY_INTERVAL` | How often the agent re-describes its host | `24h` |

These are a **starting position only**. Once the agent is enrolled the control
plane owns both, and a later edit to the file is overwritten at the next
check-in — the console is meant to be the one place you look.

To see exactly what would be sent before enabling anything, run the agent with
`--host-inventory-once`. It collects the host, prints the whole report, and
exits without contacting the platform.

Full installation detail is in the
[device agent deployment guide](../operate/deployment/device-agent-deployment.md),
including the exact command list per operating system.

### Queueing a remote collection

Remote collection is an interrogation job of type `host_inventory` against a
device that already has SSH credentials configured, and it must name the agent
that will run it — the collection runs *from* an agent that can reach the
target. Local collection is agent-originated, so there is no such thing as a
queued local job.

**Windows targets are reached by PowerShell over SSH.** WinRM is recognised and
**refused**, with an error that says so rather than failing obscurely. The
minimum supported Windows version for remote collection is **Windows Server 2019
(or Windows 10 1809) or later**, which is where the OpenSSH Server feature this
relies on is available.

## What a collection becomes

A host inventory is not a crypto finding, and it does not go down that path. It
becomes four things on one asset:

- **Identity** — the agent id (local mode only), the hardware serial, the host
  name and fully-qualified name, and the MAC address of each real, permanently
  assigned interface. Virtual interfaces and randomised MAC addresses are
  deliberately ignored: they are regenerated per boot or per container start, so
  minting identity from one produces a brand-new asset every time the machine
  restarts.
- **Facts** — the operating system, hardware and interface values above, each
  recorded as measured by the agent.
- **Endpoints** — one for every listening socket. A socket that has *stopped*
  listening is marked closed rather than deleted, because the host stating a
  socket is gone is a real answer worth keeping. Nothing about the cryptography
  on those endpoints is claimed: a host inventory observes that something is
  listening, never what it negotiates.
- **Software** — every installed package, on the asset's Software tab.

### It is held at intake

The asset lands in **Discovery → Approvals**, waiting for you, with the class
`unknown_host`. Two things follow from that:

- **The class is left coarse on purpose.** The collector measured an operating
  system name and a hardware model; deciding what *kind* of thing that makes the
  machine is a rule's job, not a measurement. A plausible-looking guess is what
  gets bulk-approved, so the platform does not make one here.
- **A second collection lands on the first one's asset**, through the ordinary
  identification engine — the agent id first, then serial, then MAC address,
  then names. Where the match is confident enough and your auto-accept threshold
  allows it, it is accepted without you; otherwise the proposal waits in
  Approvals alongside everything else. See
  [Asset Approval](./asset-approval.md).

If the host's address falls inside a network segment you have set to
auto-approve, the asset skips the queue like any other discovery.

## Where it shows up

| Where | What you see |
|---|---|
| **Discovery → Sensors & Agents**, on the agent's row | *"Last host inventory: 2h ago — 412 packages, 18 listeners"*. It is a separate line from the job counts because it answers a different question: a host inventory is not work anybody queued, so an agent busy interrogating firewalls that has never described its own host still reads as healthy on "47 jobs · 2h ago". The line is **absent** when the agent has never reported one — usually because local collection was never turned on. |
| **Discovery → Approvals** | The host waiting to be admitted, the first time it is seen. |
| The asset's **Software** tab | Every package the collection found, with its version and where it came from. |
| **Inventory → Software** | The same software across every asset — who has what version of what. |
| The asset's **Services & Endpoints** tab | One row per listening socket, with the owning process name. |

A count that is simply missing means the step did not complete — "18 listeners"
with no package count is a host whose package database could not be read, and it
is shown that way rather than as "0 packages".

## Related

- [Device Agent Deployment](../operate/deployment/device-agent-deployment.md) — installing the agent, and the exact commands run per OS
- [Sensor Registration & Management](./SENSOR_REGISTRATION.md) — registering the agent in the first place
- [Discovery](./discovery.md) — the other ways things reach your inventory
- [Asset Approval](./asset-approval.md) — the queue a collected host waits in
- [SBOM Upload](./sbom.md) — the other way software installs reach an asset
