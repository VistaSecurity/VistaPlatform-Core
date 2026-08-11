# Viewing Frameworks, Controls & Measurements

Your compliance score comes from evaluating your inventory against **frameworks** — each a set of **controls**, and each control backed by one or more **measurements** (the actual rules). The **Frameworks** browser lets you open any published framework and read its controls and exactly what each one measures, in plain language. Nothing is marked failing without a rule you can see here.

This is the companion to the [Algorithm Reference](./algorithm-reference.md): one explains the cryptographic verdicts, the other explains the compliance verdicts.

## Where to find it

**Risk & Compliance → Posture → Frameworks** tab.

Anyone who can view the Posture page can browse it — no special permission, and you do **not** need to have activated a framework to read its controls and measurements.

## What you can do

### My frameworks vs. all published

The browser opens on **My frameworks** — the frameworks you've activated, which are the ones producing your posture score. Each card shows the framework's score, control count, and how many controls are failing.

Switch to **All published** to explore the entire catalogue. Frameworks you haven't activated still show a **preview score** — what you would score against them today, given your current inventory — so you can see where you'd stand before deciding to activate.

### Open a framework to read its controls

Click any framework to open its control list. Each control shows its identifier, title, and baseline severity, and is flagged when it's cryptography-related.

### Expand a control to see how it's measured

Expand a control to read:

- its **description**, and
- **how it's measured** — each rule written as a sentence, for example:
  - *"Passes when RSA key size is at least 2,048 bits."*
  - *"Flags any certificate signature algorithm matching the pattern `sha1`."*
  - *"Passes when certificate validity is at most 398 days."*

If a control has no rule configured, it says so (and passes by default).

## Why this matters

A compliance score is only trustworthy if you can see what's behind it. The Frameworks browser turns "you're at 72%" into "here are the controls, and here is the exact rule each one applies" — so you can judge a finding, prioritize remediation, and explain your posture to an auditor.

> Frameworks, controls, and measurements are authored centrally by platform administrators (or, for your own internal standards, via **Settings → Policies → Custom Policies** in the Enterprise edition). The Frameworks browser is read-only — it's for understanding what you're measured against.
