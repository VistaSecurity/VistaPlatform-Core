# Connecting a model provider

Vista Platform is **AI-native and never AI-dependent**. Every place a model could
help sits behind a seam with a rule-based behaviour that runs whether or not one
is configured, so a deployment that never reads this page is complete: the CBOM
comparison still writes its summary, findings still carry their remediation
guidance, the end-of-life catalogue is still consulted, assets are still
classified, and inventory is still searched with the query language.

Connecting a provider is what turns on the five generative capabilities listed
on **Settings → AI assistant**. Nothing in scoring, compliance evaluation,
approval or signing goes anywhere near it — see
[AI assistant](../../features/ai-assistant.md) for what each capability does and
what it never does.

> **Edition.** The model clients ship only in the Enterprise image line. A Core
> install that sets these values gets a warning in the pod log and no change in
> behaviour, and the AI assistant page reports the edition as the reason rather
> than blaming the configuration.

## Who can set a provider, and which one answers

There are three places a provider can come from. For any one organization, the
first of these that exists is the one its prompts go to:

1. **The organization's own**, connected by its administrator on
   **Settings → AI assistant** — where you allow that (see
   [Letting organizations connect their own](#letting-organizations-connect-their-own)).
2. **The default you set in the admin console**, under **Settings → AI
   assistant**. No restart, no Helm.
3. **The one named at install**, in the chart's `ai.*` values (below).

A default set in the admin console **overrides** the one set at install; the
admin page shows both and says which is in effect. Platform features that belong
to no organization — the catalogue's **Propose with AI**, drafting into the
shared framework catalogue — use 2 or 3 and never an organization's own
provider.

Two decisions stay with you as the operator whichever route you use:

1. **Whether organizations may use their own endpoint at all**, because it is
   your egress.
2. **Whether an organization's endpoint may be on a private address**, because
   an address someone else types should not be able to reach into your network
   unless you have said so. Off by default.

Two others belong to each tenant, on their own AI assistant page: a kill switch
that stops every generative call for their organization, and an opt-in to storing
the text of their questions in their audit trail. You do not set those and cannot
override them.

## In the admin console

**Settings → AI assistant** (platform administrator, `platform.settings`).

**Default model provider.** Choose the provider, enter the address, model and
API key, press **Test connection** to try exactly what is in the form, then
**Save**. It takes effect on the next request. For a model on a private or
in-cluster address — your own Ollama beside the platform — turn on **This
endpoint is on a private network**. **Clear** removes it, and the provider set
at install (if any) takes over.

The API key is stored encrypted under the deployment's encryption key
(`platform.encryptionMasterKey`) and is never shown again; the page shows its
last four characters. A deployment with no encryption key cannot store an API
key, and the page says so.

### Letting organizations connect their own

Two switches on the same page:

| Switch | Default | What it does |
|---|---|---|
| **Organizations may connect their own provider** | On | When on, an organization can connect its own provider, which then answers for that organization instead of the default. Off makes the default the only provider anyone uses; providers organizations already saved are kept but not used. |
| **Their endpoint may be on a private network** | Off | When off, an organization can only connect a provider at a public address. |


## At install: Helm values

The rest of this page is the install-time route. It is still fully supported,
and it is the one to use when the credential should live with your other
Kubernetes Secrets rather than in the platform's database.

```yaml
ai:
  # anthropic · openai_compat · none (the default)
  provider: anthropic
  model: ""            # optional for anthropic, REQUIRED for openai_compat
  baseUrl: ""          # optional for anthropic, REQUIRED for openai_compat
  apiKey:
    existingSecret: vista-ai-credential
    existingSecretKey: api-key
```

Create the Secret first, in the release namespace:

```bash
kubectl -n vista create secret generic vista-ai-credential \
  --from-literal=api-key='sk-ant-…'
```

Then `helm upgrade` with the values above.

**This is a config-only upgrade, so every backend restarts.** The chart hashes
the shared ConfigMap into each backend's pod template, deliberately — an
`envFrom` value is read once at pod start, so without that hash the ConfigMap
would update while running pods kept the old value and nothing would say so. On a
single-node cluster, size for the surge or set `strategy: Recreate` per backend;
see the deployment guide's upgrade notes (switching a live backend to `Recreate`
needs a one-time patch first — production checklist, *Single-node clusters*).

### A self-hosted endpoint

Anything speaking the OpenAI chat-completions shape works — Ollama, vLLM, LM
Studio, llama.cpp, and most gateways:

```yaml
ai:
  provider: openai_compat
  baseUrl: http://ollama.internal:11434/v1
  model: llama3.3:70b
  allowPrivateEndpoints: true     # required for a private (RFC 1918) address
  # apiKey may be omitted entirely — openai_compat treats it as optional
```

`allowPrivateEndpoints` exists because this is the one outbound call in the
platform where a private address is the *legitimate* case. Everywhere else a
private target means someone has aimed a tenant-supplied URL at your own cluster,
and the platform refuses it. Here it may be your own model beside the platform,
so the guard becomes a decision you record rather than a rule. Leave it `false`
unless the endpoint really is yours.

The setting lifts only the private-address refusal. Loopback (`127.0.0.1`,
`localhost`) and link-local addresses (which include the cloud metadata
services) are refused whatever it says, at connect time and on every redirect,
so run the model on an address the platform can route to rather than on the
pod's own loopback. If you set
`CONNECTOR_ALLOW_PRIVATE_ENDPOINTS=false` for the platform, that switch wins and
a private model endpoint is refused too.

Write `baseUrl` as far as the server's own documentation does — `…`, `…/v1`, or
the full path — and the client appends the rest.

### With egress restricted

Each service that owns a generative capability calls the provider from its own
pod: `compliance-engine`, `cbom-service`, `inventory-service` and
`admin-service`. `auth-service` calls it too, for the **Test connection** button
on an organization's AI assistant page. All five are in the chart's
`networkPolicy.externalEgressBackends`, so `networkPolicy.egressEnabled: true`
lets them reach an endpoint outside the cluster — the default's, and any an
organization connects.

A model served **inside the cluster** is different: its address falls in
`networkPolicy.clusterInternalCIDRs`, which that rule excludes. Add a
NetworkPolicy of your own that lets those five services reach it, as for an
in-cluster proxy — see
[Outbound connections](outbound-connections.md#restricting-egress-with-networkpolicy).

### All the values

| Value | Meaning |
|---|---|
| `ai.provider` | `""` / `none` · `anthropic` · `openai_compat`. A misspelling is refused at install time, naming the field. |
| `ai.baseUrl` | Endpoint. Optional for `anthropic`, required for `openai_compat`. |
| `ai.model` | Model id. Optional for `anthropic`, required for `openai_compat`. |
| `ai.allowPrivateEndpoints` | Permit a private (RFC 1918) address. Loopback and link-local addresses stay refused. Default `false`. |
| `ai.maxTokens` | Response cap. Default 16000. |
| `ai.timeout` | Per-**attempt** HTTP timeout, e.g. `"120s"`. A call may be retried up to three times. |
| `ai.apiKey.envVar` | Name of the variable the client reads the credential from. Defaults to `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`. |
| `ai.apiKey.existingSecret` | Secret in the release namespace holding it. |
| `ai.apiKey.existingSecretKey` | Key inside that Secret. Default `api-key`. |

## Where the credential goes, and why everywhere

For the install-time route, the platform's configuration **has no field that can
hold a key**. It holds the *name* of an environment variable, and reads that
variable at the moment of use — so rotating the key is picked up by the next
request with no restart, and a configuration row that leaks is a configuration
row. That is why you will never see a credential on the AI assistant page or in
the app ConfigMap.

A provider set in the admin console, or by an organization, stores its key in
the database instead, encrypted under `platform.encryptionMasterKey`. Nothing
returns it: the settings pages show its last four characters. A provider stored
that way never falls back to the install-time key — an organization's endpoint
that has no key of its own is sent none.

The chart injects the Secret as an environment variable on **every backend**, not
only the four that own a generative capability. That is deliberate:
`GET /tenant/ai` is the single availability answer both user interfaces ask
before rendering any AI control, it is served by auth-service, and the Anthropic
client refuses to construct without a credential. An auth-service without the key
would report "no provider" and hide every AI control in the product while the
capability underneath worked perfectly.

## Checking it took

Open **Settings → AI assistant** as a tenant administrator. The **Model
provider** row names the provider kind and says **Provided by this deployment**;
the capabilities table shows **On** for the five generative rows. Status **No
provider** there means the image line has the clients and nothing is set for
that organization. For the install-time route, check the pod log for the warning
`ai-settings` writes on startup, and confirm the ConfigMap actually carries the
keys:

```bash
kubectl -n vista get cm vista-vistaplatform-config -o jsonpath='{.data.AI_PROVIDER}'
```

An empty result with `ai.provider` set in your values means the release was not
upgraded with that file.

## Turning it off

Clear the default in the admin console, and set `ai.provider: ""` (or `none`)
and upgrade if one was named at install. Every capability reverts to the
behaviour in the **Without AI** column of the AI assistant page for every
organization that has not connected its own, and nothing else changes. Delete
the Secret separately if you want the install-time credential gone. To stop
organizations' own providers as well, turn off **Organizations may connect
their own provider**.

## Related

- [AI assistant](../../features/ai-assistant.md) — what each capability does, and the two tenant controls
- [Audit Logging](../../guides/audit-logging.md) — where the record of every model call lands
- [Data Processing Agreement](../legal/data-processing-agreement.md) — the processor relationship a hosted provider creates
