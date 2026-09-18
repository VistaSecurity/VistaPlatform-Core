// Reachability for the agent settings surface, per
// FEATURE_IMPLEMENTATION_FRAMEWORK: "a feature is done only when it is
// reachable by a user and gated correctly, and no layer ships without its
// consumer."
//
// agent-config.test.ts pins the HELPERS, and every one of those assertions
// stays green with the line that wires the panel into the page deleted. So this
// reads the page and the drawer and checks the wiring itself.
//
// Each assertion corresponds to a deletion that compiles, typechecks and leaves
// every other test passing:
//
//   - drop `onRow` from the agents table → the drawer exists and nothing can
//     open it, which is precisely the state agents were in before this feature:
//     a fleet you can look at and cannot administer;
//   - drop <AgentDetailDrawer> from the page → the selected agent goes nowhere;
//   - drop the Fleet defaults button → the one control that moves a whole fleet
//     is unreachable, and the endpoint behind it has no caller;
//   - drop <SettingsPanel> from the drawer → the Settings tab renders empty and
//     the config endpoints have no reader;
//   - drop the sensors.manage check → a viewer is shown controls that will 403.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const readRaw = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

// Every assertion in this file claims a line of CODE exists. A comment carrying
// the same literal satisfies a naive string match, and that has now defeated a
// check here three times: twice on prose comments, and once when review
// commented out a JSX prop — `{/* version={q.data.version} */}` — which is a
// routine debugging move, not a contrivance. So nothing here reads a source
// file raw.
//
// Comments are removed by the TypeScript PARSER, not by pattern matching. Three
// attempts preceded this one and each was defeated by review:
//
//   1. Two regexes. `/* ... */` matched non-greedily from the first opener, so
//      an opener inside a string ran to the next real `*/`, eating live code.
//      Harmless while every assertion here was positive and failed CLOSED;
//      dangerous the moment `read` also fed NEGATIVE assertions, because a
//      region nothing sees passes silently.
//   2. A guard that threw on that input. It turned "swallows silently" into
//      "throws on the inputs I thought of" — and review found two more that
//      carry no quote at all: an opener inside a `//` comment, and one inside a
//      regex character class, `/[/*]/`.
//   3. A hand-written scanner. It lexed strings, template literals, regexes and
//      comments correctly, and got JSX catastrophically wrong: `<` and `>` were
//      in its "an expression may begin here" set, so EVERY closing tag `</Foo>`
//      opened a pseudo-regex that ran to the next `/` — usually the `{/*` of a
//      real JSX comment, which it then consumed. Comments survived, and four
//      live assertions went blind, including the very `{/* version=... */}`
//      mutation this file exists to catch. Review reproduced it verbatim.
//
// The lesson is the one this feature kept teaching in other forms: a guard that
// approximates a rule it does not implement will be wrong in a direction nobody
// predicted. TypeScript already knows where the comments are. Ask it.
//
// Cost is a parse per file, nine files, once. Correctness is the parser's.
const stripComments = (src: string, rel = 'inline.tsx'): string => {
  // ScriptKind by EXTENSION, and the parse is CHECKED. Both halves matter, and
  // review of the parser version found this the hard way: parsing everything as
  // TSX means a `.ts` file using an idiom that is legal TypeScript and illegal
  // TSX — an angle cast `<string>y`, or a generic arrow `<T>(x: T) => x` —
  // fails to parse. A failed parse absorbs the malformed region as JSX
  // children, no token carries the comments as trivia, and this function
  // returns the source with NOTHING removed. Silently.
  //
  // That is reachable by an ordinary, correct code change: write a generic
  // arrow in sensor-config-queries.ts and tsc, eslint and vitest all stay
  // green while every assertion over that file quietly becomes satisfiable by
  // commented-out code. The throw is what makes the degradation loud.
  const kind = rel.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(rel, src, ts.ScriptTarget.Latest, true, kind);
  // parseDiagnostics is internal to the compiler, hence the cast. There is no
  // public way to ask "did this parse", and the alternative — a full Program —
  // costs a type-check of the whole app to answer a question about one file.
  const diagnostics = (sf as unknown as { parseDiagnostics?: readonly unknown[] }).parseDiagnostics ?? [];
  if (diagnostics.length) {
    throw new Error(
      `${rel}: ${diagnostics.length} parse error(s) — comments would not be removed, ` +
        'so every assertion over this file would become satisfiable by a comment.',
    );
  }
  const ranges: ts.CommentRange[] = [];
  const visit = (node: ts.Node) => {
    ts.getLeadingCommentRanges(src, node.getFullStart())?.forEach((r) => ranges.push(r));
    ts.getTrailingCommentRanges(src, node.getEnd())?.forEach((r) => ranges.push(r));
    // getChildren(), not forEachChild(): tokens carry trivia too, and a JSX
    // comment `{/* ... */}` hangs off the closing brace TOKEN. forEachChild
    // skips tokens, which would leave exactly the comments that matter.
    node.getChildren(sf).forEach(visit);
  };
  visit(sf);

  // Blanked, not deleted, and newlines kept: offsets stay put so a `.slice()`
  // assertion still measures the same region, and `a/*x*/b` cannot become the
  // identifier `ab`, which is nowhere in the file.
  const chars = [...src];
  for (const r of ranges) {
    for (let i = r.pos; i < r.end && i < chars.length; i++) {
      if (chars[i] !== '\n') chars[i] = ' ';
    }
  }
  return chars.join('');
};
const read = (rel: string) => stripComments(readRaw(rel), rel);

/** The source between a landmark and the end of the construct it opens.
 *
 *  These windows used to be byte counts — `.slice(0, 400)`. That worked while
 *  comments were DELETED; they are blanked now, so a comment occupies its full
 *  width in the window and a few added lines could push an anchor out of range
 * and produce a red with no apparent cause. Review of flagged it as the
 *  first place to look if one of these ever failed mysteriously, which is
 *  reason enough not to leave it as a number.
 *
 *  `until` is the token that closes the construct, so the window is as long as
 *  the construct is and no longer. A missing landmark or terminator throws
 *  rather than silently measuring the rest of the file. */
const regionFrom = (src: string, from: string, until: string): string => {
  const start = src.indexOf(from);
  if (start < 0) throw new Error(`landmark not found: ${from}`);
  const end = src.indexOf(until, start + from.length);
  if (end < 0) throw new Error(`terminator not found after ${from}: ${until}`);
  return src.slice(start, end + until.length);
};

const page = read('./sensors-page.tsx');
const drawer = read('./agent-detail-drawer.tsx');
const modal = read('./agent-fleet-defaults-modal.tsx');
const sensorModal = read('./sensor-fleet-defaults-modal.tsx');
const sensorDrawer = read('./sensor-detail-drawer.tsx');
const panel = read('./settings-panel.tsx');

// The stripper's own guard. Review of showed the block regex swallowing
// live code behind a comment opener hidden in a string, and — because `read`
// now feeds the NEGATIVE assertions too — a hard-coded settings list surviving
// the very check that forbids it. The demonstration is reproduced verbatim
// here, because a limit that is only described in a comment is a limit nobody
// finds out about until it bites.
describe('comments are removed by the parser, not by pattern matching', () => {
  // Inputs that defeated the three hand-written versions. The first three
  // SWALLOWED live code so a negative assertion never saw it; the fourth is the
  // JSX case that made positive assertions blind and is checked against the real
  // sources further down as well.
  const swallowers = [
    ['an opener inside a string', "const sep = '/*';"],
    ['an opener inside a line comment', '// the stripper eats from /* onwards'],
    ['an opener inside a regex character class', 'const re = /[/*]/;'],
  ] as const;

  for (const [what, prefix] of swallowers) {
    it(`does not swallow code after ${what}`, () => {
      const src = `${prefix}\nconst hardcoded = ['log_level'];\n/* an ordinary block comment */\nconst after = 1;`;
      const stripped = stripComments(src);
      expect(stripped).toContain('log_level');
      expect(stripped).toContain('const after = 1;');
      expect(stripped).not.toContain('an ordinary block comment');
    });
  }

  it('removes a JSX comment rather than treating </tag> as a regex', () => {
    // The hand-written scanner put `<` and `>` in its "an expression may begin
    // here" set, so every closing tag opened a pseudo-regex that ran to the
    // next `/` — usually the `{/*` of a real JSX comment, which it swallowed.
    // Comments survived, and commented-out code satisfied assertions meant to
    // prove that code was live.
    const src = [
      'const C = () => (',
      '  <div>',
      '    <Panel />',
      '    {/* <Panel version={q.data.version} /> */}',
      '  </div>',
      ');',
    ].join('\n');
    const stripped = stripComments(src, 'c.tsx');
    expect(stripped).toContain('<Panel />');
    expect(stripped).not.toContain('version={q.data.version}');
  });

  it('strips a .ts file using an idiom that is illegal in TSX', () => {
    // A generic arrow is legal TypeScript and a parse error in TSX. Parsing
    // every file as TSX made this file's comments survive silently — the
    // regression review found in the parser version. Extension picks the
    // ScriptKind; the parse assert catches whatever the extension cannot.
    const src = 'const id = <T>(x: T) => x;\n// a comment that must not survive\nconst a = 1;';
    const stripped = stripComments(src, './queries.ts');
    expect(stripped).not.toContain('must not survive');
    expect(stripped).toContain('const a = 1;');
  });

  it('refuses a file it could not parse rather than returning it unstripped', () => {
    // A failed parse yields a source with NO comments removed. Returning that
    // is the silent pass this whole file exists to prevent, so it throws.
    expect(() => stripComments('<<<>>>???\n/* survives a failed parse */\nconst a = 1;', './broken.tsx')).toThrow(
      /parse error/,
    );
  });

  it('still removes the comments it is there to remove', () => {
    expect(stripComments('const a = 1; // note\n/* block */ const b = 2;')).not.toContain('note');
    expect(stripComments('const a = 1; // note\n/* block */ const b = 2;')).toContain('const b = 2;');
    // The two cases earlier versions got wrong in opposite directions: a URL
    // must survive, and a colon must not shield a comment from removal.
    expect(stripComments("const u = 'https://x/y';")).toContain('https://x/y');
    expect(stripComments('const k = "x"; // path: ./sensor-config-queries.ts')).not.toContain(
      'sensor-config-queries',
    );
    // A glob is a string, not a hazard. The guard that threw on this was the
    // second failed attempt.
    expect(stripComments("const g = 'src/**/*.ts';")).toContain('src/**/*.ts');
  });

  it('does not join tokens a comment separated, and keeps offsets', () => {
    // `return/* gap */x` is two tokens; DELETING the comment would produce the
    // identifier `returnx`, which is nowhere in the file. Blanking also keeps
    // every offset, so a `.slice()` assertion measures the same region it did
    // before anything was stripped.
    //
    // The first version of this test used `const a/* gap */b = 2`, which is not
    // valid TypeScript — and the parse assert added above caught it, which is
    // the assert demonstrating itself on its own author.
    const src = 'function f() { return/* gap */x; }';
    const stripped = stripComments(src);
    expect(stripped).not.toContain('returnx');
    expect(stripped).toContain('return');
    expect(stripped).toHaveLength(src.length);
  });
});

describe('an agent is reachable from the fleet table', () => {
  it('the page imports and renders the drawer', () => {
    expect(page).toContain('import { AgentDetailDrawer');
    expect(page).toMatch(/<AgentDetailDrawer\b/);
  });

  it('the agents table opens it on a row click', () => {
    // The assertion is anchored to the AGENTS table, not to the file: the
    // sensors table above it has had an onRow all along, so a file-wide search
    // for "onRow" would pass with the agents one deleted.
    // The agents table's own props, not the first 400 characters after them.
    //
    // The table now carries two row kinds (the in-cluster platform agent, whose
    // row comes from `sensors`, and the enrolled agents from `device_agents`),
    // so onRow branches. Both branches are asserted: the platform row must open
    // the SENSOR drawer — the agent drawer would call
    // device-interrogation-service's per-agent config endpoints with a sensor
    // id and 404 — and the enrolled rows must still open the agent drawer.
    const agentsTable = regionFrom(page, 'cols={AGENT_COLS}', 'render={(r) => (');
    expect(agentsTable).toMatch(/onRow=\{\(r\) => \(r\.kind === 'platform' \? setSelected\(r\.sensor\) : setSelectedAgent\(r\.agent\)\)\}/);
  });
});

describe('fleet defaults are reachable', () => {
  it('the page has the button and renders the modal', () => {
    // Anchored to the CONTROL, not to the words: the first version of this
    // assertion matched /Fleet defaults/ anywhere in the file and passed
    // happily against the comment above the button while the button itself was
    // gone. An assertion a comment can satisfy is not an assertion.
    expect(page).toMatch(/onClick=\{\(\) => setFleetDefaultsOpen\(true\)\}[\s\S]{0,160}Agent defaults/);
    expect(page).toContain('import { AgentFleetDefaultsModal }');
    expect(page).toMatch(/<AgentFleetDefaultsModal\b/);
  });

  it('the modal renders the settings panel rather than its own form', () => {
    expect(modal).toContain('import { SettingsPanel }');
    expect(modal).toMatch(/<SettingsPanel\b/);
    expect(modal).toMatch(/scope="fleet"/);
  });
});

describe('the settings surface is wired to the API', () => {
  it('the drawer renders the panel and passes the device scope', () => {
    expect(drawer).toContain('import { SettingsPanel }');
    expect(drawer).toMatch(/<SettingsPanel\b/);
    expect(drawer).toMatch(/scope="device"/);
  });

  it('the PANEL renders the version badge', () => {
    // The drawer passing the prop is one half; the panel doing something with
    // it is the other, and the likelier regression. Review deleted the whole
    // version block from settings-panel.tsx and the suite stayed green — a
    // feature present in every layer and invisible on screen, which is the
    // exact contract this file opens by claiming to enforce.
    expect(panel).toMatch(/versionNote\(version\)/);
  });

  it('the drawer passes the version block to the panel', () => {
    // The panel renders the badge; the drawer has to hand it the data. Without
    // this the whole version-visibility feature is present in every layer and
    // invisible on screen.
    expect(drawer).toMatch(/version=\{q\.data\.version\}/);
  });

  it('the drawer reads and writes through the config queries', () => {
    expect(drawer).toMatch(/useAgentConfig\(/);
    expect(drawer).toMatch(/useSaveAgentConfig\(/);
  });

  it('the panel actually calls save rather than only rendering fields', () => {
    expect(panel).toMatch(/await save\(overridesToSend\(/);
  });

  it('a successful save with JSON-null arrays cannot crash the panel', () => {
    // Go encodes a nil slice as `null`. The settings panel then did
    // `result.adjusted.map` after turning host_observation_dns on — the write
    // landed, the ErrorBoundary swallowed the drawer.
    expect(panel).toMatch(/setResult\(saveResultFrom\(/);
  });

  it('passes its own scope to overridesToSend', () => {
    // Belt and braces. `scope` is a required parameter, so dropping it is a
    // compile error — but TS2554 says "expected 3 arguments", which tells a
    // reader the arity and not the stake. The stake is that at fleet scope the
    // wrong answer CLEARS every untouched fleet default and moves every agent
    // inheriting them, which is what happened.
    expect(panel).toMatch(/overridesToSend\(settings, edited, scope\)/);
  });
});

describe('gating', () => {
  it('editing is gated on sensors.update in both surfaces', () => {
    for (const [name, src] of [['drawer', drawer], ['modal', modal]] as const) {
      expect(src, `${name} must gate editing`).toMatch(
        /hasPermission\(TENANT_PERMISSIONS\.sensors\.update\)/,
      );
    }
  });

  it('the panel hides its controls when the caller cannot edit', () => {
    // canEdit false must remove the Save button, not merely grey it: a control
    // that submits and 403s is worse than one that is absent.
    expect(panel).toMatch(/\{canEdit && \(/);
  });
});

describe('what the panel is NOT allowed to do', () => {
  it('does not carry its own list of settings', () => {
    // The registry lives on the platform. A hard-coded list here would be a
    // second source of truth, free to drift, and a setting added to the
    // platform would silently not appear.
    //
    // The keys are read from shared/agentconfig/settings.go rather than listed
    // here. A hand-written list caught a hard-coded setting only by coincidence
    // of which three keys it happened to name, and it could never catch a
    // setting added AFTER the test was written — which is the case that
    // matters, because that is what "the panel must not need changing" means.
    const registry = readFileSync(
      fileURLToPath(new URL('../../../../shared/agentconfig/settings.go', import.meta.url)),
      'utf8',
    );
    const keys = [...registry.matchAll(/^\s*Key\w+\s+Key = "([a-z0-9_]+)"$/gm)].map((m) => m[1]);
    expect(keys.length, 'no setting keys parsed from the registry — this check is inert').toBeGreaterThan(8);
    for (const key of keys) {
      expect(panel, `settings-panel.tsx must not hard-code ${key}`).not.toContain(key);
    }
  });

  it('does not decide confirmations for itself', () => {
    // The server decides; the panel asks and shows what comes back. A client
    // that could waive a confirmation by not sending the flag would make the
    // condition on which DNS decoding became settable meaningless.
    expect(panel).toContain('NeedsConfirmation');
  });
});

// Restart must be reachable, gated correctly, and honest about what it
// does — a backend endpoint with no caller is the orphan this project forbids,
// and this one ends somebody's collection until a service manager intervenes.
describe('restart is reachable and honest', () => {
  it('the drawer renders a restart control and calls the endpoint', () => {
    const control = drawer.slice(drawer.indexOf('function RestartSection'));
    expect(control).toMatch(/useRequestAgentRestart\(/);
    expect(control).toMatch(/restart\.mutate\(\)/);
  });

  it('the Settings tab actually renders it', () => {
    // Anchored to the caller, not the file: the component can exist complete
    // and unrendered, which is how the settings panel nearly shipped invisible.
    expect(drawer).toMatch(/<RestartSection\b/);
  });

  it('is gated on sensors.manage, not sensors.update', () => {
    // Disruptive, not configuration. The rest of this surface is update; this
    // one deliberately is not.
    const control = drawer.slice(drawer.indexOf('function RestartSection'));
    expect(control).toMatch(/hasPermission\(TENANT_PERMISSIONS\.sensors\.manage\)/);
  });

  it('warns that an unsupervised agent stops, BEFORE the click', () => {
    // The one way this disappoints. An operator should meet it while they can
    // still change their mind, so the words live in the confirm step rather
    // than in the success message.
    const control = drawer.slice(drawer.indexOf('function RestartSection'));
    const confirmBlock = control.slice(control.indexOf('{confirming &&'), control.indexOf('{restart.isSuccess'));
    expect(confirmBlock).toMatch(/stop instead of restarting/i);
  });
});

// The sensor half of the same surface. Sensors had a Control tab
// already — NICs, air-gapped, tags — so the failure mode here is not an
// unreachable page but a settings panel quietly absent from a tab that looks
// complete without it.
describe('sensor settings are reachable', () => {
  it('the sensor drawer renders the panel at device scope', () => {
    expect(sensorDrawer).toContain("import { SettingsPanel }");
    expect(sensorDrawer).toMatch(/<SettingsPanel\b/);
    expect(sensorDrawer).toMatch(/scope="device"/);
  });

  it("the sensor's Control TAB renders the settings section", () => {
    // Anchored to the tab, not to the file. The section is its own component,
    // so deleting <SensorSettingsSection/> from ControlTab leaves the panel,
    // the queries and the scope all present in the file and the settings
    // unreachable — which is exactly what the first version of this test
    // missed when I mutated it.
    // ControlTab's body, bounded by its own closing brace rather than by a
    // byte count that a comment can push an anchor out of.
    const controlTab = regionFrom(sensorDrawer, 'function ControlTab', '\n}');
    expect(controlTab).toMatch(/<SensorSettingsSection\b/);
  });

  it('the sensor drawer passes the version block to the panel', () => {
    // sensor-manager has served this field since and nothing rendered it
    // until now — a layer without a consumer, which a reachability audit of the
    // whole feature turned up before anyone asked for the badge.
    expect(sensorDrawer).toMatch(/version=\{q\.data\.version\}/);
  });

  it('the sensor drawer reads and writes through the sensor config queries', () => {
    expect(sensorDrawer).toMatch(/useSensorConfig\(/);
    expect(sensorDrawer).toMatch(/useSaveSensorConfig\(/);
  });

  it('the page offers sensor fleet defaults and renders their modal', () => {
    expect(page).toMatch(/onClick=\{\(\) => setSensorDefaultsOpen\(true\)\}[\s\S]{0,160}Sensor defaults/);
    expect(page).toContain('import { SensorFleetDefaultsModal }');
    expect(page).toMatch(/<SensorFleetDefaultsModal\b/);
  });

  it('the sensor modal renders the shared panel at fleet scope', () => {
    expect(sensorModal).toContain("import { SettingsPanel }");
    expect(sensorModal).toMatch(/scope="fleet"/);
  });

  it('editing sensor settings is gated on sensors.update in both surfaces', () => {
    for (const [name, src] of [['sensor drawer', sensorDrawer], ['sensor modal', sensorModal]] as const) {
      expect(src, `${name} must gate editing`).toMatch(
        /hasPermission\(TENANT_PERMISSIONS\.sensors\.update\)/,
      );
    }
  });
});

// Two mutations passed review that should not have: repointing the sensor
// queries at the AGENT endpoints typechecked and left 1527 tests green, and
// reverting the agent route's permission to manage went unnoticed. Both are
// "the wiring is right" claims that nothing checked.
// The layer BELOW the JSX prop. Pinning `version={q.data.version}` proved the
// drawer passes the prop and nothing more — the agent's query never put
// `version` in the object, so the badge was silently absent while the endpoint
// served it, the type declared it, and the prop assertion stayed green. A
// producer that never produces is invisible to a check on its consumer.
describe('the version block is produced, not just passed', () => {
  for (const [name, src] of [
    ['agent', read('./agent-config-queries.ts')],
    ['sensor', read('./sensor-config-queries.ts')],
  ] as const) {
    it(`the ${name} config query returns the version it received`, () => {
      expect(src, `${name} query must return version`).toMatch(/version:\s*data\.version/);
    });
  }
});

// The change history. agent_config_audit was written on every save and
// read by nothing — the orphaned layer the feature framework forbids, and the
// one carrying the DNS decoder's recorded-confirmation obligation. These pin
// the whole chain: query → section → drawer.
describe('the configuration change history is reachable', () => {
  const history = read('./config-history.tsx');

  it('each runtime has a history query against its own service', () => {
    expect(read('./agent-config-queries.ts')).toMatch(
      /clients\.devices\.GET\('\/agents\/\{id\}\/config\/history'/,
    );
    expect(read('./sensor-config-queries.ts')).toMatch(
      /clients\.sensors\.GET\('\/sensors\/\{sensor_id\}\/desired-config\/history'/,
    );
  });

  it('both drawers render the history section', () => {
    for (const [name, src] of [['agent', drawer], ['sensor', sensorDrawer]] as const) {
      expect(src, `${name} drawer must import it`).toContain("import { ConfigHistorySection }");
      expect(src, `${name} drawer must render it`).toMatch(/<ConfigHistorySection\b/);
    }
  });

  it('the section shows who changed what, not merely that something changed', () => {
    // The obligation is "DNS decoding was turned ON, by this account, when" —
    // a list of keys that moved, with their before and after. A section that
    // only printed timestamps would satisfy a laxer assertion and answer
    // nothing an operator asked.
    expect(history).toMatch(/values_before/);
    expect(history).toMatch(/values_after/);
    expect(history).toMatch(/settingLabel\(/);
  });

  it('it does not fetch until opened', () => {
    // An audit table queried by every drawer glance is a different defect from
    // the one this closes.
    for (const src of [drawer, sensorDrawer]) {
      expect(src).toMatch(/useState\(false\)/);
      expect(src).toMatch(/onOpen=\{\(\) => setHistoryOpen\(true\)\}/);
    }
  });
});

describe('each runtime talks to its own service', () => {
  // Comments are stripped by `read` at module scope — see the note there for
  // why, and for the stripper's two known limits. The COUNT assertions below
  // are the backstop for the second of them.
  const sensorQueries = read('./sensor-config-queries.ts');
  const agentQueries = read('./agent-config-queries.ts');

  it('sensor queries use the sensor-manager client and its paths', () => {
    // Repointing these at clients.devices typechecks — both clients expose a
    // config surface — so an operator would edit a sensor and silently write
    // an agent's settings.
    expect(sensorQueries).toMatch(/clients\.sensors\.GET\('\/sensors\/\{sensor_id\}\/desired-config'/);
    expect(sensorQueries).toMatch(/return saveResultFrom\(data\)/);
    expect(sensorQueries).toMatch(/clients\.sensors\.(GET|PUT)\('\/sensors\/config\/defaults'/);
    expect(sensorQueries).not.toMatch(/clients\.devices\./);

    // Wrong service is one hazard; wrong PATH within the right service is the
    // worse one. Exactly one write goes to the fleet-defaults path — a
    // per-sensor save that landed there would rewrite the tenant's defaults
    // and move every inheriting sensor.
    const defaultsWrites = sensorQueries.match(/clients\.sensors\.PUT\('\/sensors\/config\/defaults'/g) ?? [];
    expect(defaultsWrites).toHaveLength(1);
    const perSensorWrites = sensorQueries.match(/clients\.sensors\.PUT\('\/sensors\/\{sensor_id\}\/desired-config'/g) ?? [];
    expect(perSensorWrites).toHaveLength(1);
  });

  it('agent queries use the device-interrogation client and its paths', () => {
    expect(agentQueries).toMatch(/clients\.devices\.GET\('\/agents\/\{id\}\/config'/);
    expect(agentQueries).toMatch(/clients\.devices\.PUT\('\/agents\/\{id\}\/config'/);
    expect(agentQueries).toMatch(/return saveResultFrom\(data\)/);
    expect(agentQueries).not.toMatch(/clients\.sensors\./);
  });
});
