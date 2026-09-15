// Reachability for workstream 2.10b (FEATURE_IMPLEMENTATION_FRAMEWORK).
//
// "A feature is done only when it is reachable by a user and gated correctly,
// and no layer ships without its consumer."
//
// class-proposals.test.ts pins the HELPERS — `countBySource` counts a fourth
// kind, `queryNoteKind` accounts for a fourth read, `readClassProposalPage`
// reads `total` rather than the array length. Every one of those stays green
// with the line that WIRES it into the page deleted, which is the trap CLAUDE.md
// names twice: a correct fix shipped with tests that pass when the one load-
// bearing line is removed. So this reads approvals-page.tsx and inventory-page.tsx
// and checks the wiring itself.
//
// Each assertion below corresponds to a deletion that compiles, typechecks, and
// leaves every other test passing:
//
//   - drop `classProposalsQ` from `queryNote([…])` → "Nothing awaiting review"
//     prints over a failed read, sending a reviewer away from work they have;
//   - drop `allClassProposals` from `countBySource(…)` → the source chips
//     under-report the queue they claim to describe;
//   - drop `<ClassProposalRow>` → the endpoint has no reader and the proposals
//     accumulate unseen;
//   - drop the error block → a failed read renders as an empty section;
//   - drop `classProposalsQ.data?.total` from the Inventory banner → the number
//     sends a user to a page with more work on it than it admitted.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const approvalsPage = read('./approvals-page.tsx');
const inventoryPage = read('../inventory/inventory-page.tsx');

describe('class proposals are reachable in Approvals', () => {
  it('the page imports the row component', () => {
    expect(approvalsPage).toContain('import { ClassProposalRow }');
  });

  it('the page actually RENDERS it', () => {
    // An imported-but-unrendered component is the orphan this check exists for.
    expect(approvalsPage).toMatch(/<ClassProposalRow/);
    expect(approvalsPage).toContain('class-proposals-section');
  });

  it('the page reads the proposals and can decide them BOTH ways', () => {
    expect(approvalsPage).toContain('useClassProposals');
    expect(approvalsPage).toContain('useDecideClassProposal');
    // A queue that can only accept is a queue that grows — and rejecting is
    // load-bearing here beyond tidiness: the `class_rejected` row is what stops
    // intake proposing the same class on the next observation.
    expect(approvalsPage).toMatch(/action:\s*'accept'/);
    expect(approvalsPage).toMatch(/action:\s*'reject'/);
  });

  it('accepting carries the class the reviewer CHOSE', () => {
    // A conflict proposal offers a choice and the server refuses to pick. A row
    // that dropped the chosen key would 400 on every conflict, which is the
    // commonest reason a class proposal exists at all.
    expect(approvalsPage).toMatch(/onAccept=\{\(classKey\)/);
    expect(approvalsPage).toMatch(/classKey\s*\}\)/);
  });

  it('a failed class read has its own visible error state', () => {
    // Rendering a failed read as an empty section tells a reviewer there is
    // nothing to do. The merge read had exactly this bug; the relationship read
    // inherited the guard; a fourth kind added without it reintroduces it.
    expect(approvalsPage).toContain('class-proposals-error');
  });

  it('the empty-state guard covers the class read', () => {
    expect(approvalsPage).toMatch(/queryNote\(\[[^\]]*\bclassProposalsQ\b[^\]]*\]/);
  });

  it('the source facet counts the fourth row kind', () => {
    expect(approvalsPage).toMatch(/countBySource\([^)]*\ballClassProposals\b[^)]*\)/);
  });

  it('the section header shows the tenant-wide total, not the page length', () => {
    // `classProposals.length` here is how the merge queue once told a tenant
    // with 132 proposals that it had 50.
    expect(approvalsPage).toMatch(/Class proposals \(\{classProposalTotal\}\)/);
  });
});

describe('the pending banner counts class proposals', () => {
  it('reads the fourth total', () => {
    expect(inventoryPage).toContain('useClassProposals');
    expect(inventoryPage).toMatch(/classProposalsQ\.data\?\.total/);
  });
});

// Workstream 4.2: a second producer. The API layer grew `model_id`,
// `model_probability` and `model_reasons`, and each of them is useless if the
// row does not read it — an endpoint with no reader, in miniature.
//
// The row is JSX and these tests are pure, so this reads the file. The
// alternative is a rendering test that passes with the whole model branch
// deleted, because the fixture it renders is a rule proposal.
describe('the row tells a model proposal apart from a rule one', () => {
  const row = read('./class-proposal-row.tsx');

  it('reads model_id to decide which provenance it is', () => {
    // Without this the chip says "Rule" over a class no rule argued, which is
    // false provenance on the one thing a reviewer uses to decide how hard to
    // look.
    expect(row).toMatch(/proposal\.model_id/);
    expect(row).toContain("data-provenance");
    expect(row).toMatch(/byModel \? 'Model' : 'Rule'/);
  });

  it('shows the probability as the model states it', () => {
    // `confidence` carries the same number, but reading THAT would print a
    // rule's 0.50–0.95 assertion and a model's calibrated probability under one
    // label, as if they were the same kind of quantity.
    expect(row).toMatch(/proposal\.model_probability/);
    expect(row).toContain('proposed by model (P=');
  });

  it('renders the reasons behind it', () => {
    // A model cannot cite a source URL the way a rule can. The three feature
    // contributions are the whole of its argument, and a row that dropped them
    // would leave a reviewer with a percentage to rubber-stamp.
    expect(row).toMatch(/proposal\.model_reasons/);
    expect(row).toContain('class-proposal-model-reasons');
  });

  it('still lets a reviewer take the other candidate when one was named', () => {
    // The model settles a rule conflict by picking one of the tied classes. The
    // person reviewing it has to be able to take the other — the server allows
    // exactly that set — so the chooser renders whenever candidates exist, not
    // only when nothing was proposed.
    expect(row).toMatch(/const offersChoice = conflicting\.length > 0/);
    expect(row).toMatch(/onAccept\(offersChoice \? chosen : undefined\)/);
  });
});
