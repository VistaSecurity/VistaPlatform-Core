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

If a control has no rule configured, it says so — and it is reported as **Not assessed**, not as a pass. See [Control results](#control-results-pass-fail-and-not-assessed) below.

## Control results: PASS, FAIL, and Not assessed

Every control ends up in exactly one of three states. You see them on the control
grid under **Risk & Compliance → Posture**, and on each control group under
**Risk & Compliance → Findings → By Control**.

| Result | What it means | What put it there |
|---|---|---|
| **PASS** | The control was checked, and nothing in scope violated it. | Zero open findings against that control. |
| **FAIL** | The control was checked, and at least one thing violated it. | One or more open findings against that control — *any* severity, on *any* asset. |
| **Not assessed** | The control was not checked, so we are not claiming anything about it. | No measurement rule configured, nothing in scope to check, or the check itself failed. Hover the result to see which. |

Three things are worth spelling out, because each one used to work differently:

- **A single violation fails the control.** If one certificate out of two hundred
  breaks the rule, the control reads FAIL. It goes back to PASS when the last
  violation is cleared. A partial pass would let a real gap hide behind a
  comfortable number.
- **Severity does not decide the result.** A control violated by a Low-severity
  finding fails exactly like one violated by a Critical finding. Severity still
  does two jobs — it labels each finding, and it weights the score (see below) —
  but it no longer decides pass or fail. Previously it did, which meant a
  Low-severity control could show PASS while carrying open findings.
- **There is no WARN.** The old intermediate result earned no score either way,
  so it read as "not failing" while counting as a failure in the arithmetic.
  Anything that used to show WARN now shows FAIL, and its severity tells you how
  urgent it is.

### Why a control shows "Not assessed"

Hovering a **Not assessed** result tells you which of three situations applies:

- **No measurements configured** — the control exists in the framework but nobody
  has written the rule that measures it yet. Common in a framework still being
  authored, or in a Custom Policy you are part-way through.
- **Nothing in scope to check** — the rule is fine, but you have no matching
  inventory. A control about SSH host keys is not assessed if the platform has
  not discovered any SSH services yet.
- **Check failed** — the platform tried to measure the control and could not.
  This is a data-quality signal: it usually clears on the next evaluation, and
  it is worth raising if it persists.

None of these are a pass. Reporting them as a pass is how an empty inventory or
a half-written framework used to score 100%.

## How the score is computed

A framework's score covers **assessed controls only** — the ones that came back
PASS or FAIL. Not-assessed controls are left out of both the numerator and the
denominator, so they neither reward nor punish you.

Each assessed control counts according to its severity, so that failing something
critical costs more than failing something minor:

| Control severity | Weight |
|---|---|
| Critical | 4× |
| High | 3× |
| Med | 2× |
| Low | 1× |

The score is the weight of everything that passed, over the weight of everything
that was assessed. Alongside it you will see a **coverage** line whenever any
control was skipped — for example *"8 of 11 controls assessed"* — so the number
always comes with the size of the sample behind it.

**If nothing was assessed, there is no score.** The framework shows **—** with
*"0 of 11 controls assessed"*, never 100%. A blank score means "we have not
looked yet"; 100% means "we looked, and everything passed." Keeping those apart
is the whole point.

A worked example. A framework has 11 controls; 8 of them are assessed.

| Assessed controls | Weight each | Result | Weight passing |
|---|---|---|---|
| 2 × Critical | 4 | both PASS | 8 |
| 3 × High | 3 | 2 PASS, 1 FAIL | 6 |
| 2 × Med | 2 | both PASS | 4 |
| 1 × Low | 1 | PASS | 1 |
| **Totals** | **22 assessed** | | **19 passing** |

Score: 19 ÷ 22 = **86%**, shown with *"8 of 11 controls assessed"*.

The three unassessed controls do not appear in either number. Configure their
measurement rules, or discover the inventory they apply to, and coverage rises —
at which point the score may move in either direction, because you are now
measuring more of your estate.

### Where you see this

- **Risk & Compliance → Posture** — each activated framework's scorecard shows
  the score, the control tally, and the coverage line. Open a framework for the
  control grid, where every control shows PASS, FAIL, or Not assessed.
- **Risk & Compliance → Findings → By Control** — findings grouped by the control
  they violate, with the same result on each group header.
- **Settings → Policies → Compliance Frameworks** — the preview score on each
  framework you have not activated follows exactly the same rules, coverage line
  included. A framework you could not evaluate shows **—**, so a preview can
  never flatter itself with a 100% that nothing earned.

> **Scores may have moved when this shipped.** Frameworks whose only violations
> were low-severity previously reported as fully passing; they now report those
> failures honestly, and the score drops accordingly. Nothing about your
> inventory changed — only what we were willing to call a pass.

## Why this matters

A compliance score is only trustworthy if you can see what's behind it. The Frameworks browser turns "you're at 72%" into "here are the controls, and here is the exact rule each one applies" — so you can judge a finding, prioritize remediation, and explain your posture to an auditor.

> Frameworks, controls, and measurements are authored centrally by platform administrators (or, for your own internal standards, via **Settings → Policies → Custom Policies** in the Enterprise edition). The Frameworks browser is read-only — it's for understanding what you're measured against.
