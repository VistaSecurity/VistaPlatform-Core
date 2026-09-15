// Asset class icons resolve against the lucide-react the UI actually ships.
//
// `standards/asset-classes.yaml` names an icon per class as a bare string, so
// nothing about the type system catches a typo or an icon lucide renamed
// between majors (HelpCircle -> CircleHelp -> CircleQuestionMark happened
// twice in the v1 line). The failure mode is silent: the class facet and the
// asset page render a hole where the icon should be.
//
// The generator checks the same thing at `make generate`/`make audit` time,
// but only when the workspace has been npm-installed — which the standards CI
// job does not do. This test runs where lucide-react is unambiguously present,
// and it imports the package rather than reading its typings, so it is the
// assertion about the module the bundle will actually load.
import { describe, expect, it } from 'vitest';
import * as lucide from 'lucide-react';
import { ASSET_CLASSES, ASSET_CLASS_KEYS } from '@vistasecurity/primitives/assets';

describe('asset class icons', () => {
  it('has classes to check', () => {
    // Anchor: an empty registry would make the assertion below vacuous.
    expect(ASSET_CLASS_KEYS.length).toBeGreaterThan(20);
  });

  it('names only real lucide-react exports', () => {
    const missing = ASSET_CLASS_KEYS.filter(
      (key) => !(ASSET_CLASSES[key].icon in lucide),
    ).map((key) => `${key}: ${ASSET_CLASSES[key].icon}`);
    expect(missing).toEqual([]);
  });
});
