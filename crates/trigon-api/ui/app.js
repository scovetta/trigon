// The corpus browser.
//
// Plain ES modules. No bundler, no framework, no `node_modules`, nothing loaded off-origin — see
// `ui.rs` for why that is a decision rather than an omission.
//
// Three rules from the documents are enforced here rather than trusted:
//
//   1. **The two denominators are never merged.** A package that did not reproduce and a build we
//      could not run are different findings, and this page has no code path that divides one by a
//      total containing the other. There is no "success rate" anywhere in this file.
//   2. **Never checked is not a pass.** It is rendered as its own state, in its own colour.
//   3. **Absent is not zero.** A missing timing, cost or count renders as "not recorded", because
//      a number we failed to read is not a measurement of nothing.

const $ = (sel, root = document) => root.querySelector(sel);
const view = $('#view');

/* ---- small helpers ------------------------------------------------------ */

const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    // Through CSSOM, never `setAttribute('style', …)`.
    //
    // The page's own Content-Security-Policy is `style-src 'self'`, which blocks the `style`
    // *attribute* — so every proportional bar was written, silently dropped by the browser, and
    // rendered at the track's full width. Four outcome counts, four identical bars, and a page
    // that looked fine until somebody compared the lengths to the numbers beside them.
    //
    // CSP deliberately does not govern CSSOM, so assigning each property is both allowed and the
    // reason `'unsafe-inline'` does not have to be added to get a bar chart.
    else if (k === 'style') for (const d of v) n.style.setProperty(d[0], d[1]);
    else n.setAttribute(k, v === true ? '' : String(v));
  }
  // `flat(Infinity)`, not `flat()`. `kv()` returns a `[dt, dd]` pair, so a panel built from
  // `rows.map(kv)` arrives two levels deep and a single flatten left the pairs as arrays — which
  // the text node path then stringified into `[object Object]`. It rendered correctly wherever
  // each `kv()` was a direct argument, so the bug was invisible in four panels out of five.
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
};

const api = async (path) => {
  const r = await fetch(path, { headers: { accept: 'application/json' } });
  const body = await r.json().catch(() => ({ error: 'unreadable', detail: r.statusText }));
  if (!r.ok) throw Object.assign(new Error(body.detail || r.statusText), { body, status: r.status });
  return body;
};

// An absent value is never rendered as a zero. This is the one-line version of the rule the record
// type spends three paragraphs on, and it exists because every accidental `?? 0` in a renderer
// turns "we did not measure this" into "this measured nothing".
const orAbsent = (v, render = (x) => x) =>
  v === null || v === undefined ? el('span', { class: 'empty', text: 'not recorded' }) : render(v);

// A string that is present and empty. Distinct from absent for a *blob* — a zero-byte network
// transcript means the build's egress was completely accounted for and nothing crossed — but for a
// name it means nobody filled the field in, and rendering it as a blank cell hides that.
const blankAsAbsent = (v) => (typeof v === 'string' && v.trim() === '' ? null : v);

const ago = (iso) => {
  if (!iso) return '';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const s = Math.max(0, (Date.now() - then) / 1000);
  const [n, unit] =
    s < 90 ? [s, 'second'] :
    s < 5400 ? [s / 60, 'minute'] :
    s < 172800 ? [s / 3600, 'hour'] :
    s < 5184000 ? [s / 86400, 'day'] : [s / 2592000, 'month'];
  const r = Math.round(n);
  return `${r} ${unit}${r === 1 ? '' : 's'} ago`;
};

const secs = (n) => n === null || n === undefined ? null : (n < 1 ? `${Math.round(n * 1000)} ms` : `${n < 60 ? n.toFixed(1) : Math.round(n)} s`);

const bytes = (n) => {
  if (n === null || n === undefined) return null;
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${i === 0 ? v : v.toFixed(1)} ${u[i]}`;
};

/* ---- the verdict vocabulary --------------------------------------------- */

// Sentences rather than enum names. A reader who is not us should not have to know that
// `normalized_with_caveats` is a verdict and not an error.
const VERDICT = {
  exact: ['exact', 'The rebuilt bytes are the published bytes. Nothing had to be normalized for this to hold.'],
  normalized: ['normalized', 'The bytes differ and every way in which they differ was removed by a named, compiled-in pass. This is a clean match.'],
  normalized_with_caveats: ['normalized, with caveats', 'A match, reached using a pass that rewrites content or that a person or a model wrote. The caveat is about how we got there, not about the package.'],
  divergent: ['divergent', 'The rebuilt artifact is not the published one, and the difference survived every pass.'],
};

const verdictTag = (outcome) =>
  el('span', { class: `tag ${outcome || 'none'}`, text: outcome ? (VERDICT[outcome]?.[0] ?? outcome) : 'no verdict' });

const seal = (attested) =>
  attested
    ? el('span', { class: 'seal signed', title: 'A statement has been signed for this run: the claim was re-derived from the artifact bytes before signing.', text: '◆ attested' })
    : el('span', { class: 'seal unsigned', title: 'No statement has been signed. This outcome is a claim by whichever worker computed it, not one that has been independently re-derived.', text: '◇ unattested' });

/* ---- routing ------------------------------------------------------------ */

const routes = [
  [/^\/$/, () => browse(new URLSearchParams(location.search))],
  [/^\/runs\/([^/]+)$/, (m) => detail(decodeURIComponent(m[1]))],
  [/^\/targets\/(.+)$/, (m) => target(decodeURIComponent(m[1]))],
  [/^\/artifacts\/([0-9a-fA-F:]+)$/, (m) => artifact(m[1])],
];

async function route() {
  const path = location.pathname;
  for (const [re, fn] of routes) {
    const m = path.match(re);
    if (m) {
      try {
        await fn(m);
      } catch (e) {
        view.replaceChildren(
          el('div', { class: 'err' },
            el('strong', { text: 'That did not work. ' }),
            el('span', { text: e.message || String(e) })),
          el('p', {}, el('a', { href: '/', text: '← back to the corpus' })),
        );
      }
      return;
    }
  }
  view.replaceChildren(
    el('p', { class: 'empty', text: 'No page at that address.' }),
    el('p', {}, el('a', { href: '/', text: '← back to the corpus' })),
  );
}

const go = (href) => { history.pushState({}, '', href); route(); };

document.addEventListener('click', (e) => {
  const a = e.target.closest('a');
  if (!a || a.target || a.hasAttribute('download')) return;
  const url = new URL(a.href, location.origin);
  if (url.origin !== location.origin || url.pathname.startsWith('/v1/')) return;
  e.preventDefault();
  go(url.pathname + url.search);
});
window.addEventListener('popstate', route);

/* ---- what the server already told us ------------------------------------ */

// `trigon serve` replaces a marker in the document with this island, so the first painted frame
// carries the corpus summary instead of the word "Loading". A copy served from a CDN has no island
// and everything below falls through to a fetch — the page works either way, which is what keeps
// the file the same bytes in both places.
const BOOT = (() => {
  try {
    const n = document.getElementById?.('boot');
    return n ? JSON.parse(n.textContent) : null;
  } catch {
    return null;
  }
})();

/* ---- the header's mode pill --------------------------------------------- */

let HEALTH = BOOT?.health ?? null;
async function health() {
  if (HEALTH) { paintMode(); return HEALTH; }
  HEALTH = await api('/v1/health').catch(() => null);
  paintMode();
  return HEALTH;
}

function paintMode() {
  const pill = $('#mode');
  if (HEALTH && pill) {
    const stopped = HEALTH.divergence_publication === 'stopped';
    pill.hidden = false;
    pill.className = `mode${stopped ? ' stopped' : ''}`;
    pill.textContent = stopped
      ? 'divergence publication stopped'
      : HEALTH.principal === 'anonymous' ? 'public view' : 'operator view';
    pill.title = HEALTH.principal === 'anonymous'
      ? 'You are seeing only what the publication gate released: two agreeing attempts, a restricted egress tier, and no stabilizer a person or a model wrote.'
      : 'You are reading a store directly. Everything is shown, including runs the publication gate would hold back from a public reader.';
  }
}

/* ---- browse ------------------------------------------------------------- */

let FIRST_VIEW_SPENT = false;
let DETAIL_BOOT_SPENT = false;

// How a run ended without a verdict, in a sentence. Each is a statement about a different thing,
// and the whole reason `terminal` is a field rather than a flag is that collapsing them makes a
// corpus uninterpretable.
const TERMINAL = {
  'no-strategy': 'No rung had a recipe for this package. That is a statement about our coverage, not about the package.',
  'build-failed': 'The build ran and did not finish. What stopped it is named below.',
  void: 'Neither a pass nor a failure: the published artifact reached the build over the network, so whatever came out is evidence of nothing.',
  failed: 'Our infrastructure, the registry, or a policy stopped this before the package was ever tested.',
};

const BAR_COLOUR = {
  exact: 'var(--ok)', normalized: 'var(--ok)',
  normalized_with_caveats: 'var(--caveat)',
  divergent: 'var(--fail)',
  infra: 'var(--structural)', bug: 'var(--fail)', upstream: 'var(--one-side)',
  policy: 'var(--caveat)', build: 'var(--void)', unclassified: 'var(--faint)',
  'no-strategy': 'var(--faint)', 'build-failed': 'var(--void)',
  void: 'var(--structural)', failed: 'var(--one-side)',
};

function bars(obj, onPick) {
  const entries = Object.entries(obj);
  if (!entries.length) return el('p', { class: 'empty', text: 'nothing in this column yet' });
  const max = Math.max(...entries.map(([, n]) => n));
  return el('div', { class: 'bars' }, entries.map(([k, n]) =>
    el('div', { class: 'bar-row' },
      onPick
        ? el('button', { class: 'k', title: `show only ${k}`, onclick: () => onPick(k) }, k.replace(/_/g, ' '))
        : el('span', { class: 'k', text: k.replace(/_/g, ' ') }),
      el('div', { class: 'bar-track' },
        el('div', {
          class: 'bar-fill',
          style: [['width', `${(n / max) * 100}%`], ['background', BAR_COLOUR[k] || 'var(--dim)']],
        })),
      el('span', { class: 'n', text: n }))));
}

async function browse(params) {
  await health();
  // The boot island is only good for an unfiltered first view: it is the whole corpus's summary,
  // and a filtered page needs counts for the filter. Spending it exactly once is the difference
  // between a first frame with content and one more round trip before anything appears.
  const bootable = BOOT?.stats && BOOT?.runs && ![...params].length && !FIRST_VIEW_SPENT;
  FIRST_VIEW_SPENT = true;
  const [stats, page] = bootable
    ? [BOOT.stats, BOOT.runs]
    : await Promise.all([
        api('/v1/stats'),
        api('/v1/runs?' + new URLSearchParams({ limit: '50', ...Object.fromEntries(params) })),
      ]);

  const setFilter = (k, v) => {
    const p = new URLSearchParams(location.search);
    if (v === null || v === '' || p.get(k) === v) p.delete(k); else p.set(k, v);
    p.delete('cursor');
    go('/?' + p.toString());
  };

  // The two denominators, side by side and never added together. The left one is about packages;
  // the right one is about us. `18-management-ui.md` §3 is the whole argument, and it is the
  // reason there is no third card here reading "94% success".
  const denominators = el('div', { class: 'denominators' },
    el('section', { class: 'denominator' },
      el('h2', { text: 'What the rebuilds said' }),
      el('p', { class: 'lede' },
        el('span', { class: 'count', text: stats.evidence }),
        ' run(s) reached a verdict with no guard tripped. These are statements about packages.'),
      bars(stats.by_outcome, (k) => setFilter('outcome', k))),

    el('section', { class: 'denominator' },
      el('h2', { text: 'What never became evidence' }),
      el('p', { class: 'lede' },
        el('span', { class: 'count', text: stats.runs - stats.evidence }),
        ' run(s) never reached a verdict. Mostly our problem, not the package’s — and kept out of the column on the left for exactly that reason.'),
      bars(stats.by_fault, (k) => setFilter('fault', k)),
      el('p', { class: 'never-checked' },
        'A package with no row here has not been checked. ',
        el('strong', { text: 'Never checked is not a pass' }),
        ' — it is the absence of an answer.')),

    Object.keys(stats.by_withheld || {}).length
      ? el('section', { class: 'denominator' },
          el('h2', { text: 'Held back from this view' }),
          el('p', { class: 'lede' },
            'Results the publication gate has not released. Counted here rather than quietly missing, because a page showing part of a corpus without saying so has a denominator that is a lie.'),
          bars(stats.by_withheld))
      : null,
  );

  const filters = el('div', { class: 'filters' },
    el('input', {
      type: 'search', placeholder: 'package, failure code, or an artifact sha256…',
      value: params.get('q') || '', 'aria-label': 'Search the corpus',
      title: 'A package name, a failure code, or the sha256 of an artifact you are holding.',
      onchange: (e) => {
        const v = e.target.value.trim();
        // 64 hex characters, with or without a `sha256:` prefix, is somebody holding an artifact
        // and asking about it — not a substring to match against package names.
        const hex = v.replace(/^sha256:/i, '');
        if (/^[0-9a-f]{64}$/i.test(hex)) go(`/artifacts/${hex}`);
        else setFilter('q', v);
      },
    }),
    select('ecosystem', params.get('ecosystem'), Object.keys(stats.by_ecosystem || {}), setFilter),
    select('outcome', params.get('outcome'), Object.keys(VERDICT), setFilter),
    select('fault', params.get('fault'), Object.keys(stats.by_fault || {}), setFilter),
    el('button', {
      class: 'chip', 'aria-pressed': params.get('kind') === 'evidence',
      onclick: () => setFilter('kind', 'evidence'), title: 'Only runs that reached a verdict',
    }, 'reached a verdict'),
    el('button', {
      class: 'chip', 'aria-pressed': params.get('kind') === 'failed',
      onclick: () => setFilter('kind', 'failed'), title: 'Only runs that did not',
    }, 'did not'),
    [...params].length ? el('button', { class: 'chip', onclick: () => go('/'), text: 'clear' }) : null,
  );

  const table = runTable(page.rows);

  const withheldNote = page.withheld
    ? el('p', { class: 'withheld-note' },
        el('strong', { text: `${page.withheld} of ${page.total} matching run(s) are not shown here.` }),
        ' They have not passed the publication gate — most often because only one attempt has been made, and one attempt cannot tell a deterministic recipe from a lucky one.')
    : null;

  const more = page.next
    ? el('p', {}, el('button', {
        class: 'chip',
        onclick: () => setFilter('cursor', page.next),
        text: 'next page →',
      }))
    : null;

  document.title = 'Trigon — the rebuild corpus';
  view.replaceChildren(denominators, filters, table, withheldNote, more);
}

/* ---- one package, every run against it --------------------------------- */

// The version ladder. A verdict on one version says little on its own: the question a person has
// after reading "divergent" is whether the neighbouring versions did the same thing, and until this
// existed the only way to ask was to type the name into the search box and read the table sideways.
async function target(purl) {
  await health();
  const rows = await api(`/v1/targets/${encodeURIComponent(purl)}`);
  document.title = `${purl} — Trigon`;
  view.replaceChildren(
    el('p', {}, el('a', { href: '/', text: '← the corpus' })),
    el('div', { class: 'verdict-head' },
      el('h1', { text: purl.replace(/^pkg:[^/]+\//, '') }),
      el('p', { class: 'purl mono', text: purl })),
    el('p', { class: 'sentence' },
      `${rows.length} run(s) against this package. Each is a separate attempt at a separate version, and nothing here is an average of them.`),
    runTable(rows),
  );
}

/* ---- lookup by what you are holding ------------------------------------- */

// The one query that works without a naming authority: somebody holding a tarball can ask about it
// without knowing what we call it. `19-distribution-and-lookup.md` makes this the primary key and
// the purl the secondary index, and a corpus browser with no way to type a digest inverts that.
async function artifact(digest) {
  await health();
  document.title = `${digest.slice(0, 16)}… — Trigon`;
  let rows = [];
  let miss = null;
  try {
    rows = await api(`/v1/artifacts/${encodeURIComponent(digest)}`);
  } catch (e) {
    miss = e;
  }
  view.replaceChildren(
    el('p', {}, el('a', { href: '/', text: '← the corpus' })),
    el('div', { class: 'verdict-head' },
      el('h1', { text: 'Lookup by artifact digest' }),
      el('p', { class: 'purl mono', text: digest })),
    miss
      ? el('div', { class: 'withheld-note' },
          el('strong', { text: 'Never checked. ' }),
          'Nothing published covers that artifact — which is the absence of an answer and not a pass. ',
          el('span', { class: 'empty', text: miss.message }))
      : el('div', {},
          el('p', { class: 'sentence' },
            `${rows.length} run(s) cover exactly those bytes.`),
          runTable(rows)),
  );
}

function select(name, current, options, setFilter) {
  const s = el('select', {
    'aria-label': name,
    onchange: (e) => setFilter(name, e.target.value),
  }, el('option', { value: '', text: `any ${name}` }));
  for (const o of options.sort()) {
    s.append(el('option', { value: o, selected: o === current, text: o.replace(/_/g, ' ') }));
  }
  return s;
}

/* ---- the run table, shared by every listing ----------------------------- */

function runTable(rows) {
  if (!rows.length) return el('p', { class: 'empty', text: 'No run matches that.' });
  return el('table', { class: 'runs' },
    el('thead', {}, el('tr', {},
      el('th', { text: 'package' }),
      el('th', { class: 'opt', text: 'ecosystem' }),
      el('th', { text: 'verdict' }),
      el('th', { text: 'failure' }),
      el('th', { class: 'opt', text: 'fault' }),
      el('th', { class: 'opt', text: 'statement' }),
      el('th', { text: 'ran' }))),
    el('tbody', {}, rows.map((e) => el('tr', {},
      el('td', { class: 'pkg' },
        el('a', { href: `/runs/${encodeURIComponent(e.id)}` },
          el('span', { text: e.name }),
          e.version ? el('span', { class: 'ver', text: ' @ ' + e.version }) : null)),
      el('td', { class: 'opt', text: e.ecosystem }),
      el('td', {}, e.outcome
        ? verdictTag(e.outcome)
        // How it ended, not the word "failed". `no-strategy` means we have no recipe for this
        // package, which is a statement about us; a reader who sees "failed" reads it as one about
        // the package.
        : el('span', {
            class: `tag ${e.terminal === 'void' ? 'void' : 'none'}`,
            title: TERMINAL[e.terminal] || 'This run reached no verdict.',
            text: (e.terminal || 'no verdict').replace(/-/g, ' '),
          })),
      el('td', {}, e.failure_code
        ? el('span', { class: 'mono', title: 'the failure signature this run was classified under' }, e.failure_code)
        : el('span', { class: 'empty', text: '—' })),
      el('td', { class: 'opt' }, e.fault ? el('span', { class: 'tag fault', text: e.fault }) : ''),
      el('td', { class: 'opt' }, seal(e.attested)),
      el('td', { class: 'when', text: ago(e.started) }),
    ))));
}

/* ---- one run ------------------------------------------------------------ */

async function detail(id) {
  await health();
  // The server injects the run when the page was entered on a permalink, which is what makes a
  // shared link paint its verdict rather than the word "Loading". It is spent once: a second
  // `/runs/...` reached by clicking is a fetch, because the island describes the entry point.
  const booted = BOOT?.run && !DETAIL_BOOT_SPENT && BOOT.run.entry?.id === id;
  DETAIL_BOOT_SPENT = true;
  const { entry, record } = booted
    ? BOOT.run
    : await api(`/v1/runs/${encodeURIComponent(id)}`);
  document.title = `${entry.name} — Trigon`;

  const head = el('div', { class: 'verdict-head' },
    el('h1', { text: entry.version ? `${entry.name} @ ${entry.version}` : entry.name }),
    el('p', { class: 'purl mono' },
      el('a', {
        href: `/targets/${encodeURIComponent(record.target.replace(/@[^@]*$/, ''))}`,
        title: 'every run against this package',
        text: record.target,
      })),
  );

  const [, sentence] = VERDICT[entry.outcome] || [];
  const verdict = el('div', {},
    el('div', { class: 'verdict-line' },
      entry.outcome
        ? verdictTag(entry.outcome)
        : el('span', {
            class: `tag ${record.terminal === 'void' ? 'void' : 'none'}`,
            text: (record.terminal || 'no verdict').replace(/-/g, ' '),
          }),
      seal(entry.attested),
      entry.publication.state !== 'published'
        ? el('span', { class: 'tag void', title: withheldTitle(entry.publication), text: entry.publication.state === 'void' ? 'published as void' : 'not published' })
        : null),
    el('p', { class: 'sentence' },
      sentence
        || TERMINAL[record.terminal]
        || 'This run finished without producing a verdict. What stopped it is below.'),
    entry.publication.state !== 'published'
      ? el('p', { class: 'withheld-note' },
          el('strong', { text: entry.publication.state === 'void' ? 'Published as void: ' : 'Held back: ' }),
          withheldTitle(entry.publication))
      : null,
  );

  // The chain, in the shape the run page in `watch` uses: the sequence a reader walks to decide
  // whether to believe the verdict, left to right, one fact per link.
  const src = record.source || {};
  const chain = el('div', { class: 'ribbon' }, [
    src.commit ? [el('span', { text: 'commit ' }), el('b', { class: 'mono', text: src.commit.slice(0, 8) })] : null,
    record.strategy_digest ? [el('span', { text: 'strategy ' }), el('b', { class: 'mono', text: record.strategy_digest.slice(0, 8) })] : null,
    record.derivation ? [el('span', { text: 'derived ' }), el('b', { text: record.derivation.replace(/_/g, ' ') })] : null,
    [el('span', { text: 'egress ' }), el('b', { text: record.environment.egress })],
    [el('span', { text: 'guard ' }), el('b', { text: record.environment.guard_manifest ? `${record.environment.guarded_members ?? 0} member(s) watched` : 'not armed' })],
    entry.outcome ? [el('span', { text: 'verdict ' }), el('b', { text: entry.outcome.replace(/_/g, ' ') })] : null,
  ].filter(Boolean).flatMap((bit, i) => i ? [el('span', { class: 'arrow', text: '→' }), ...bit] : bit));

  const panels = [
    panel('What ran', el('dl', { class: 'kv' },
      kv('base image', el('span', { class: 'mono', text: record.environment.base_image })),
      // An empty string here is a field nobody wrote, not an isolation mechanism named "". The
      // records in the store carry exactly that, and a blank row beside "base image" reads as a
      // rendering fault rather than as missing data.
      kv('isolation', orAbsent(blankAsAbsent(record.environment.isolation))),
      kv('egress tier', record.environment.egress),
      kv('accountable', record.environment.attestable
        ? 'yes — everything that crossed into the build was recorded'
        : el('span', { class: 'empty', text: 'no complete account of the build’s network exists' })),
      record.environment.registry_moment ? kv('registry pinned to', record.environment.registry_moment) : null,
      kv('guard', record.environment.guard_manifest
        ? `armed, watching ${record.environment.guarded_members ?? 0} member(s)`
        : el('span', { class: 'empty', text: 'nobody looked' })),
    )),

    src.repo_url ? panel('Where the source came from', el('dl', { class: 'kv' },
      kv('repository', el('a', { href: src.repo_url, rel: 'noreferrer noopener', text: src.repo_url })),
      kv('commit', el('span', { class: 'mono', text: src.commit || '—' })),
      src.subdir ? kv('built in', el('span', { class: 'mono', text: src.subdir })) : null,
      kv('found by', (src.how || 'unrecorded').replace(/_/g, ' ')),
    )) : null,

    record.failure ? panel('What stopped it', el('dl', { class: 'kv' },
      kv('signature', el('span', { class: 'mono', text: record.failure.code })),
      record.failure.subject ? kv('subject', el('span', { class: 'mono', text: record.failure.subject })) : null,
      kv('whose', el('span', { class: 'tag fault', text: record.failure.fault })),
      kv('worth retrying', record.failure.retryable ? 'yes — running it again unchanged could answer differently' : 'no — the same run reaches the same place'),
      kv('worth repairing', record.failure.repairable ? 'yes' : 'no — a repair attempt has no prospect here'),
    )) : null,

    record.declines?.length ? panel('Why no rung answered', el('ul', { class: 'assumptions' },
      record.declines.map((d) => el('li', { text: d })))) : null,

    record.assumptions?.length ? panel('What this had to assume', el('div', {},
      el('ul', { class: 'assumptions' }, record.assumptions.map((a) => el('li', { text: a }))),
      el('p', { class: 'note empty' },
        'A verdict reached under assumptions is a different claim from one reached under none, which is why they are listed beside it rather than folded into it.'))) : null,

    record.guard_trips?.length ? panel('Why this is void', el('div', {},
      el('ul', { class: 'assumptions' }, record.guard_trips.map((g) => el('li', { text: g }))),
      el('p', { class: 'note empty' },
        'The artifact under test reached the build over the network. Whatever came out may be perfectly honest and we cannot tell, which is exactly what void means.'))) : null,

    panel('What it cost', costs(record)),

    panel('The evidence', el('div', { class: 'evidence' },
      evidenceLink('the comparison', `/v1/runs/${id}/comparison`, entry.has.comparison, 'The full member-by-member comparison, with every stabilizer that fired.'),
      evidenceLink('the build log', `/v1/runs/${id}/log`, entry.has.build_log, 'Unredacted, so it is served to a principal and not to the internet.'),
      evidenceLink('what crossed the network', `/v1/runs/${id}/network`, entry.has.network_transcript, 'Every request the build made, as the mirror saw it.'),
      evidenceLink('the signed statement', `/v1/runs/${id}/attestation`, entry.attested, 'The product: a claim re-derived from the bytes before it was signed.'),
    )),

    panel('Timings', record.timings?.length
      ? el('dl', { class: 'kv' }, record.timings.map(([phase, s]) => kv(phase, orAbsent(s, (x) => secs(x)))))
      : el('p', { class: 'empty', text: 'no phase timings were recorded for this run' })),
  ].filter(Boolean);

  view.replaceChildren(
    el('p', {}, el('a', { href: '/', text: '← the corpus' })),
    head, verdict, chain, ...panels,
    el('p', { class: 'empty mono', text: `run ${record.id} · attempt ${record.attempt} · started ${record.started}` }),
  );
}

const withheldTitle = (pub) => ({
  awaiting_confirmation: 'held back until a second, independent attempt agrees. One attempt cannot tell a deterministic recipe from a lucky one.',
  attempts_disagree: 'two attempts at this disagreed, so the honest answer is that we do not know. That is a finding about our repeatability, not about the package.',
  open_egress: 'the build ran with unrestricted network access, so nothing it produced is evidence about the package.',
  guard_tripped: 'the build reached the published artifact over the network, so a match would prove only that it downloaded it.',
  non_builtin_stabilizer: 'a stabilizer a person or a model wrote was applied, so this publishes as void rather than as a divergence.',
  kill_switch: 'divergence publication is stopped while the false-mismatch rate is reviewed.',
  no_outcome: 'this run never reached a verdict, so there is nothing to publish.',
}[pub.because] || 'the publication gate has not released this.');

const panel = (title, body) => el('section', { class: 'panel' }, el('h2', { text: title }), body);
const kv = (k, v) => v === null ? null : [el('dt', { text: k }), el('dd', {}, v)];

function costs(record) {
  const c = record.costs;
  if (!c) {
    // The third state, and the reason it is spelled out: a record written before costs were
    // measured is not a run that was free.
    return el('p', { class: 'empty', text: 'no costs were recorded for this run. That is not the same as a run that cost nothing.' });
  }
  const rows = [
    kv('in the sandbox', orAbsent(c.build_seconds, secs)),
    kv('waiting on a model', orAbsent(c.inference_seconds, secs)),
    // `Some(0)` and absent are different answers here and the distinction is the whole point of
    // the field: a build that fetched nothing and one that was not measured are not the same run.
    kv('crossed the network', orAbsent(c.egress_bytes, bytes)),
    kv('added to the store', orAbsent(c.blob_bytes, (n) => {
      // Artifacts and logs are *subsets* of the total, never additions to it, so they are shown
      // inside it rather than beside it where somebody would add them up.
      const parts = [
        c.artifact_bytes !== null && c.artifact_bytes !== undefined ? `${bytes(c.artifact_bytes)} of it artifacts` : null,
        c.log_bytes !== null && c.log_bytes !== undefined ? `${bytes(c.log_bytes)} of it log` : null,
      ].filter(Boolean);
      return parts.length ? `${bytes(n)} — ${parts.join(', ')}` : bytes(n);
    })),
  ];
  // One row per model, never summed across them: the same token count is two orders of magnitude
  // apart in price between a local 0.5B and a frontier model, so adding them means nothing.
  for (const t of c.tokens || []) {
    rows.push(kv(`tokens · ${t.model}`,
      `${t.calls} call(s) · ${t.input} in, ${t.cached_input} of them cached · ${t.output} out`));
  }
  if (!(c.tokens || []).length) {
    rows.push(kv('models asked', el('span', { class: 'empty', text: 'none — this run was inferred without one' })));
  }
  // No dollars. There is no price table, and multiplying by a rate we typed in would put an
  // invented number on the one view whose purpose is that you do not discover the cost on an
  // invoice.
  return el('dl', { class: 'kv' }, rows.filter(Boolean));
}

function evidenceLink(label, href, present, why) {
  if (!present) {
    return el('span', { class: 'absent', title: 'This run recorded nothing of that kind. Absent is not empty.' }, label + ' — not recorded');
  }
  // A class-gated link is still shown, with the reason. Hiding it would teach a reader that the
  // evidence does not exist rather than that they are not the principal who may read it.
  const anonymous = HEALTH?.principal === 'anonymous';
  const gated = anonymous && /\/(log|network|comparison)$/.test(href);
  return gated
    ? el('span', { class: 'gated', title: why }, label + ' — needs a principal')
    : el('a', { href, title: why, text: label });
}

route();
