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

## What you are configuring

Two decisions belong to you as the operator, and neither is a tenant's:

1. **Which endpoint**, because it is your egress and your data-processing
   relationship.
2. **The credential**, because it belongs with the database password and the
   certificates rather than in a settings screen.

Two others belong to each tenant, on their own AI assistant page: a kill switch
that stops every generative call for their organization, and an opt-in to storing
the text of their questions in their audit trail. You do not set those and cannot
override them.

## Helm values

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
see the deployment guide's upgrade notes.

### A self-hosted endpoint

Anything speaking the OpenAI chat-completions shape works — Ollama, vLLM, LM
Studio, llama.cpp, and most gateways:

```yaml
ai:
  provider: openai_compat
  baseUrl: http://ollama.internal:11434/v1
  model: llama3.3:70b
  allowPrivateEndpoints: true     # required for a private or loopback address
  # apiKey may be omitted entirely — openai_compat treats it as optional
```

`allowPrivateEndpoints` exists because this is the one outbound call in the
platform where a private address is the *legitimate* case. Everywhere else a
private target means someone has aimed a tenant-supplied URL at your own cluster,
and the platform refuses it. Here it may be your own model beside the platform,
so the guard becomes a decision you record rather than a rule. Leave it `false`
unless the endpoint really is yours.

Write `baseUrl` as far as the server's own documentation does — `…`, `…/v1`, or
the full path — and the client appends the rest.

### All the values

| Value | Meaning |
|---|---|
| `ai.provider` | `""` / `none` · `anthropic` · `openai_compat`. A misspelling is refused at install time, naming the field. |
| `ai.baseUrl` | Endpoint. Optional for `anthropic`, required for `openai_compat`. |
| `ai.model` | Model id. Optional for `anthropic`, required for `openai_compat`. |
| `ai.allowPrivateEndpoints` | Permit a loopback or RFC1918 address. Default `false`. |
| `ai.maxTokens` | Response cap. Default 16000. |
| `ai.timeout` | Per-**attempt** HTTP timeout, e.g. `"120s"`. A call may be retried up to three times. |
| `ai.apiKey.envVar` | Name of the variable the client reads the credential from. Defaults to `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`. |
| `ai.apiKey.existingSecret` | Secret in the release namespace holding it. |
| `ai.apiKey.existingSecretKey` | Key inside that Secret. Default `api-key`. |

## Where the credential goes, and why everywhere

The platform's configuration object **has no field that can hold a key**. It
holds the *name* of an environment variable, and reads that variable at the
moment of use — so rotating the key is picked up by the next request with no
restart, and a configuration row that leaks is a configuration row. That is why
you will never see a credential on the AI assistant page or in the app ConfigMap.

The chart injects the Secret as an environment variable on **every backend**, not
only the four that own a generative capability. That is deliberate:
`GET /tenant/ai` is the single availability answer both user interfaces ask
before rendering any AI control, it is served by auth-service, and the Anthropic
client refuses to construct without a credential. An auth-service without the key
would report "no provider" and hide every AI control in the product while the
capability underneath worked perfectly.

## Checking it took

Open **Settings → AI assistant** as a tenant administrator. The deployment
section names the provider kind and the model; the capabilities table shows
**On** for the five generative rows. Status **No provider** there means the
image line has the clients and the environment did not reach them — check the
pod log for the warning `ai-settings` writes on startup, and confirm the
ConfigMap actually carries the keys:

```bash
kubectl -n vista get cm vista-vistaplatform-config -o jsonpath='{.data.AI_PROVIDER}'
```

An empty result with `ai.provider` set in your values means the release was not
upgraded with that file.

## Turning it off

Set `ai.provider: ""` (or `none`) and upgrade. Every capability reverts to the
behaviour in the **Without AI** column of the AI assistant page, and nothing
else changes. Delete the Secret separately if you want the credential gone.

## Related

- [AI assistant](../../features/ai-assistant.md) — what each capability does, and the two tenant controls
- [Audit Logging](../../guides/audit-logging.md) — where the record of every model call lands
- [Data Processing Agreement](../legal/data-processing-agreement.md) — the processor relationship a hosted provider creates
