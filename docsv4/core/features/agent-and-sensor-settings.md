# Agent and sensor settings

Every setting on a registered sensor or discovery agent is managed from the
console. Once a device is enrolled, you should not need to log into the host it
runs on again.

**Where:** Discovery → Sensors & Agents.

- **One sensor:** click its row, then the **Control** tab.
- **One discovery agent:** click its row, then the **Settings** tab.
- **The whole fleet:** **Sensor defaults** or **Agent defaults**, on the page
  header. They are two separate sets — a sensor and an agent share almost no
  settings, so one combined dialog would be half-irrelevant whichever fleet you
  came for.

Platform sensors run in the cluster rather than on your network and are not
configured here; they have no Control tab.

## How a setting gets its value

Three layers, weakest first:

| Layer | What it is |
|---|---|
| **Built-in default** | What the binary does when nobody has said otherwise. |
| **Fleet default** | What you have set for every sensor, or every agent, in your organization. |
| **This device** | An override on one device, which beats both. |

Each setting shows where its current value came from, so you can tell a
deliberate choice from an inherited one. **Revert to fleet defaults** removes a
device's overrides and lets it follow the fleet again.

A device that overrides a setting is **not** moved when you change that fleet
default — that is the point of an override. Devices that inherit it converge on
the new value at their next check-in, with nothing to restart and nothing to
push.

## The config file is for enrolment only

The file on the host supplies what the device needs to **register**: the
platform URL and its registration key. After that the control plane owns its
settings.

**A local edit to a managed setting is overwritten at the next check-in.** That
is intended: the console is meant to be the one place you look, and a setting
changed on a host that the console does not know about is exactly the drift this
removes.

## What "applied" means

Changing a setting does not change the device. The device changes itself, at its
next check-in, and then says so. That tab reports which of those has
happened:

| State | What it means | What to do |
|---|---|---|
| **Applied** | The device is running these settings. | Nothing. |
| **Pending** | Saved. The device picks it up at its next check-in. | Wait one check-in interval. |
| **Awaiting restart** | The device accepted the change but can only adopt it when it restarts. | Restart the device when convenient. |
| **Failed** | The device could not apply something, and says which and why. | Read the reason on the setting. |
| **Never reported** | The device has not checked in, so nothing is known about it. | Check the device is running and can reach the platform. |
| **Not reporting** | The device checks in but does not report its configuration. | Upgrade it — it is older than remote management, and waiting will not help. |

The last two are deliberately separate. One device is unreachable; the other is
running and healthy but too old to be managed, and they need different actions.

**Which settings need a restart:** on a sensor, **Host observation**, **Host
observation window** and **Host observation DNS** — all three. They change what
the sensor captures, and the capture filter is fixed when the sensor opens its
network interface, so switching a decoder on without reopening it would leave it
running and receiving nothing. Everything else takes effect at the next
check-in.

The window belongs in that list and was missing from it: it was classified as
taking effect immediately until review found that the console reported
**Applied** for a window the sensor was not yet using. Saying "applied" about
something not in force is the failure this whole surface exists to prevent.

## Settings that need confirming

A setting that starts collecting something new asks you to confirm it, naming
what begins to be collected. Two sensor settings do:

- **Host observation DNS** reads DNS *answers* only, never the questions anybody
  asked, but an answer names what was asked — so the set of names your network
  resolved becomes part of what the sensor records.
- **Actively enrich third-party TLS connections** has sensors open their own TLS
  connections to external services your network talks to, to read their
  certificates. Third parties may see those connections. See
  [Certificates of third-party TLS connections](./third-party-and-external-connections.md#certificates-of-third-party-tls-connections).

Turning either **off** needs no confirmation. Neither is ever taken from what a
device reports it is running: a confirmation is given in the console, not adopted
from a device.

Third-party TLS enrichment can also be set in an air-gapped sensor's own file; the
platform's value replaces it the first time one is delivered, and keeps replacing
it after restarts. See
[Air-gapped sensors](./third-party-and-external-connections.md#certificates-of-third-party-tls-connections).

Confirmations are recorded with the account that gave them.

## Values that get adjusted

Some settings have a floor. Ask for a host inventory every five minutes and you
will get one an hour, because a five-minute collection walks the host's whole
package database twelve times an hour.

When that happens the console **tells you**, on save. The agent has always
raised such values quietly in its own log; the difference is that now you find
out.

## What you can change

The list is per device type and the console shows the current set with a
description for each. Broadly:

- **Discovery agents** — host inventory on/off and how often, how often the
  agent asks for work, how often it reports in, and how much it logs.
- **Sensors** — active probing, third-party TLS enrichment (off by default),
  network discovery, host observation and its window, DNS decoding, the
  observation rest period, the reporting interval, and how much it logs.

A setting your device's build does not support is reported back as unsupported,
naming the version — the console will not show it as applied.

## Which version a device is running

Each device shows the version it last reported, next to the version this
platform release ships:

| Badge | What it means |
|---|---|
| **Up to date** | The device is on the version that ships with this release. |
| **Update available** | The device is older. Upgrading is a manual step — the platform does not replace binaries. |
| **Newer than the platform** | The device is ahead of this release. Normal mid-upgrade; otherwise check which binary was installed. |
| **Version unknown** | Nothing could be compared — the device has not reported a version, this release does not know its own, or either side is unparseable. |

Two different pre-releases of the same version are **not** the same build, and
are not reported as up to date. Build metadata is ignored, per the semantic
versioning spec: `1.2.3+abc` and `1.2.3+def` are the same version.

**Version unknown is never "up to date."** A comparison that could not be made
is shown as exactly that, so a device nobody can vouch for is not mistaken for
one that is current.

The expected version is the release **this platform** is running, because the
sensor and agent binaries ship from the same tag. Nothing is asked of any
external service, so this works on an air-gapped install — and it means the
platform can only report a device as behind once it has itself been upgraded.

## Permissions

Viewing these settings needs **View sensors**; changing them needs **Update
sensors**. Both apply to sensors and discovery agents alike, because they are one
fleet on one page — a role that can configure a sensor can configure an agent
beside it.

**Restarting a discovery agent** needs **Full sensor management**, a deliberate
step up. Changing a setting is configuration; restarting stops the device until
something starts it again, and that belongs with the operations that interrupt
things.

**Restarting a sensor** goes through the sensor's older command channel and
needs only **Update sensors**. The two paths are not the same age and do not yet
draw the line in the same place.

## Restarting a device

Settings marked *takes effect on restart* are adopted when the device restarts,
and both device types can be restarted from the console — by different routes,
which is worth knowing because they behave differently.

**A discovery agent:** its **Settings** tab, where **Restart** records a
*request*. The agent restarts at its next check-in.

**A sensor:** its **Control** tab, under **Send command** — choose **restart**
and send it. This is the sensor's existing command channel, which predates this
feature; the command is queued and the sensor collects it on its next
heartbeat.

**A restart is an exit.** The device stops and its service manager starts it
again — systemd, a Windows service, a container runtime. If somebody launched it
by hand rather than installing it as a service, restarting **stops it**, and it
stays stopped. The agent's Restart control says so before you confirm; the
sensor's command form does not, so it is worth knowing before you send one.

For an **agent**, asking twice is the same as asking once: the platform records
*when* you asked, and the agent restarts if it has been running since before
that moment. There is no queue to drain and nothing to cancel — once it has
restarted, the request no longer applies. An agent that never checks in never
restarts, and the request simply sits until it does.

For a **sensor**, each command is a separate queued item, so sending restart
three times queues three restarts.

## Related

- [Host inventory](./host-inventory.md) — what a discovery agent collects about
  the host it runs on, and how to turn it on.
- [Discovery](./discovery.md) — what sensors and agents do with what they find.
