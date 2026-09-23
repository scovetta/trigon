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

// The viewer's own credential, if they have pasted one.
//
// `localStorage`, deliberately and with its limits stated: it is this browser's copy of a token the
// operator issued, it never leaves the origin, and a viewer who clears it is simply anonymous
// again. It is not an account, there is no session, and nothing here can mint one — `trigon grant`
// does that on the machine holding the queue.
const TOKEN = {
  get() {
    try {
      return localStorage.getItem('trigon.token') || null;
    } catch {
      // Private windows and blocked site data both throw. Anonymous is the correct fallback.
      return null;
    }
  },
  set(v) {
    try {
      if (v) localStorage.setItem('trigon.token', v);
      else localStorage.removeItem('trigon.token');
    } catch { /* nothing to do; the page works without it */ }
  },
};

const api = async (path, opts = {}) => {
  const headers = { accept: 'application/json', ...(opts.headers || {}) };
  const token = TOKEN.get();
  if (token) headers.authorization = `Bearer ${token}`;
  // `raw` sends the body as-is. A lockfile is not JSON — `requirements.txt` certainly is not —
  // and JSON-encoding one would hand the server a quoted string to unwrap before it could parse it.
  if (opts.body !== undefined) {
    headers['content-type'] = opts.raw ? 'text/plain' : 'application/json';
  }
  const r = await fetch(path, {
    method: opts.method || 'GET',
    headers,
    body: opts.body === undefined ? undefined
      : (opts.raw ? opts.body : JSON.stringify(opts.body)),
  });
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
  [/^\/queue$/, () => queueView()],
  [/^\/jobs\/(\d+)$/, (m) => jobView(Number(m[1]))],
  [/^\/account$/, () => accountView()],
  [/^\/check$/, () => checkView()],
  [/^\/clusters$/, () => clustersView()],
  [/^\/fleet$/, () => fleetView()],
];

async function route() {
  readOpenRequest();
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
  const nav = document.getElementById?.('nav');
  if (nav) {
    nav.replaceChildren(
      el('a', { href: '/check', text: 'check a lockfile' }),
      el('a', { href: '/clusters', text: 'clusters' }),
      el('a', { href: '/fleet', text: 'fleet' }),
      el('a', { href: '/queue', text: 'queue' }),
      el('a', { href: '/account', text: ME?.principal ? ME.principal : 'sign in' }),
    );
  }
}

/* ---- the credential, and what it can do --------------------------------- */

let ME = null;
async function me(force) {
  if (ME && !force) return ME;
  ME = await api('/v1/me').catch(() => ({ principal: null, scopes: [] }));
  return ME;
}

// **Never awaited on a first paint.** Who the viewer is depends on a token this browser holds and
// the server did not see when it built the document, so `/v1/me` is a fetch no boot island can
// remove — and awaiting it put the word "Loading" back into the first frame of every page that
// did. So: paint with what is known, put the credential-dependent part in a slot, and fill the
// slot when the answer arrives. The page is correct at both instants; it is only more useful at
// the second.
// **Paint first, fetch second. Always.**
//
// This page's first frame has been the word "Loading" four separate times: the browse view, a
// permalink, the queue, and then the run detail again the moment a comparison fetch was added in
// front of `replaceChildren`. Each fix was correct and none of them generalised, because the bug is
// not in any one view — it is that `await` before a paint is easy to write and invisible until
// somebody looks at a screenshot.
//
// So: a view puts up an empty slot, hands this the promise, and carries on. The slot fills when the
// answer arrives, the frame is never blank, and a fetch that fails leaves a sentence rather than a
// gap. If you find yourself awaiting something before `view.replaceChildren`, that is the bug.
function fillLater(slot, promise, render, whenMissing) {
  promise.then((data) => {
    let parts = [];
    try {
      parts = data ? [render(data)].flat().filter(Boolean) : [];
    } catch (e) {
      // A renderer that throws would otherwise leave the placeholder up for ever — the page would
      // read as "still loading" when it is not loading and never will. Saying so is worth more
      // than the panel was.
      slot.replaceChildren(el('div', { class: 'err' },
        el('strong', { text: 'This section could not be drawn. ' }),
        el('span', { text: e.message || String(e) }),
        el('p', { class: 'note', text: 'The evidence it was drawn from is linked further down; a rendering that fails should cost you a panel, not the data.' })));
      return;
    }
    if (parts.length) slot.replaceChildren(...parts);
    else if (whenMissing) slot.replaceChildren(whenMissing());
    else slot.replaceChildren();
  });
}

function whenIdentified(slot, render) {
  if (ME) {
    slot.replaceChildren(...[render()].flat().filter(Boolean));
    return;
  }
  me().then(() => {
    slot.replaceChildren(...[render()].flat().filter(Boolean));
    paintMode();
  });
}

const mayRequest = () => !!ME?.scopes?.includes('request');

/* ---- browse ------------------------------------------------------------- */

let FIRST_VIEW_SPENT = false;
let DETAIL_BOOT_SPENT = false;
let QUEUE_BOOT_SPENT = false;
let DIFF_BOOT_SPENT = false;

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
  const ask = el('div', {});
  whenIdentified(ask, () => requestPanel(params.get('q')));
  view.replaceChildren(denominators, filters, table, withheldNote, more, ask);
}

/* ---- ask for a rebuild -------------------------------------------------- */

// Shown only where the credential actually carries the scope, and read from `/v1/me` rather than
// guessed: a form that appears and then refuses teaches a visitor that the site is arbitrary.
function requestPanel(prefill) {
  if (!mayRequest()) return null;
  const input = el('input', {
    type: 'text',
    placeholder: 'pkg:npm/left-pad@1.3.0',
    value: prefill || '',
    'aria-label': 'A package URL to rebuild',
    id: 'request-target',
  });
  const out = el('p', { class: 'note', text: '' });

  const ask = async () => {
    const target = input.value.trim();
    if (!target) return;
    out.className = 'note';
    out.textContent = 'asking…';
    try {
      const r = await api('/v1/runs', { method: 'POST', body: { target } });
      const quota = r.quota ? ` ${r.quota.spent} of ${r.quota.daily} today.` : '';
      out.replaceChildren(
        el('span', { text: r.detail + quota + ' ' }),
        r.job ? el('a', { href: `/jobs/${r.job}`, text: 'follow it →' }) : null,
      );
      await me(true);
    } catch (e) {
      out.className = 'withheld-note';
      out.textContent = e.message;
    }
  };

  return el('section', { class: 'panel' },
    el('h2', { text: 'Ask for a rebuild' }),
    el('div', { class: 'filters' },
      input,
      el('button', { class: 'chip', onclick: ask, text: 'request' })),
    out,
    el('p', { class: 'note' },
      'A request names a package and nothing else — no build recipe, no stabilizer, and no network tier. ',
      'Nothing publishes until a second, independent attempt agrees with the first.'));
}

/* ---- the queue ----------------------------------------------------------- */

async function queueView() {
  await health();
  document.title = 'Queue — Trigon';
  // The server puts the queue in the document when this page is entered directly, so the first
  // frame carries the depth rather than the word "Loading". Spent once; a return visit re-fetches,
  // because a queue a few seconds stale is the one thing this page must not show.
  const booted = BOOT?.queue && !QUEUE_BOOT_SPENT;
  QUEUE_BOOT_SPENT = true;
  const q = booted ? BOOT.queue : await api('/v1/queue');

  if (!q.depth) {
    view.replaceChildren(
      el('p', {}, el('a', { href: '/', text: '← the corpus' })),
      el('div', { class: 'verdict-head' }, el('h1', { text: 'Queue' })),
      el('p', { class: 'empty', text: q.detail }));
    return;
  }

  const rows = q.in_flight.map((j) => el('tr', {},
    el('td', { class: 'pkg' },
      el('a', { href: `/jobs/${j.job}`, text: j.target.replace(/^pkg:[^/]+\//, '') })),
    el('td', { class: 'opt', text: j.target.replace(/^pkg:/, '').split('/')[0] }),
    el('td', {}, el('span', {
      class: `tag ${j.state === 'leased' ? 'normalized_with_caveats' : 'none'}`,
      text: j.state === 'leased' ? 'building' : 'waiting',
    })),
    el('td', { class: 'n', text: `attempt ${j.attempt}` }),
  ));

  const ask = el('div', {});
  whenIdentified(ask, () => requestPanel());
  view.replaceChildren(
    el('p', {}, el('a', { href: '/', text: '← the corpus' })),
    el('div', { class: 'verdict-head' },
      el('h1', { text: 'Queue' }),
      el('p', { class: 'purl', text: 'What the fleet is about to look at. Nothing here is a finding about anybody.' })),
    el('section', { class: 'panel' },
      el('h2', { text: 'Depth' }),
      bars(q.depth)),
    ask,
    rows.length
      ? el('table', { class: 'runs' },
          el('thead', {}, el('tr', {},
            el('th', { text: 'package' }),
            el('th', { class: 'opt', text: 'ecosystem' }),
            el('th', { text: 'state' }),
            el('th', { class: 'n', text: '' }))),
          el('tbody', {}, rows))
      : el('p', { class: 'empty', text: 'Nothing waiting and nothing running.' }),
  );
}

/* ---- one job, while it runs --------------------------------------------- */

// Polled rather than streamed. `docs/22` §5.4 refuses a route that proxies to the worker — the
// reader has to survive the producer's death, and with several workers the API shares no
// filesystem with the build anyway. Events come from a table, so a worker dying mid-build leaves
// the page showing exactly how far it got.
let JOB_POLL = null;
async function jobView(id) {
  await health();
  document.title = `Job ${id} — Trigon`;
  if (JOB_POLL) clearInterval(JOB_POLL);

  const list = el('ul', { class: 'assumptions' });
  const head = el('p', { class: 'sentence', text: 'Waiting for a worker to pick this up.' });

  const draw = async () => {
    let data;
    try {
      data = await api(`/v1/jobs/${id}/events`);
    } catch {
      return;
    }
    const events = data.events || [];
    list.replaceChildren(...events.map((e) => el('li', {},
      el('strong', { text: e.phase.replace(/-/g, ' ') }),
      e.detail ? el('span', { text: ` — ${e.detail}` }) : null,
      el('span', { class: 'empty', text: `  ${ago(new Date(e.at).toISOString())}` }))));
    const last = events[events.length - 1];
    head.textContent = !last
      ? 'Waiting for a worker to pick this up.'
      : last.phase === 'recorded'
        ? 'Finished and recorded. It publishes once a second attempt agrees.'
        : last.phase === 'dead'
          ? 'Out of attempts. The row is kept, because a queue that tidies these away looks healthy while something is broken.'
          : `Running: ${last.phase}.`;
    if (last && (last.phase === 'recorded' || last.phase === 'dead') && JOB_POLL) {
      clearInterval(JOB_POLL);
      JOB_POLL = null;
    }
  };

  view.replaceChildren(
    el('p', {}, el('a', { href: '/queue', text: '← the queue' })),
    el('div', { class: 'verdict-head' }, el('h1', { text: `Job ${id}` })),
    head,
    el('section', { class: 'panel' }, el('h2', { text: 'What it has done' }), list),
  );
  await draw();
  JOB_POLL = setInterval(draw, 3000);
}

/* ---- the credential ------------------------------------------------------ */

// The one page whose whole content *is* the identity, so it cannot avoid the fetch. What it can
// avoid is painting somebody else's placeholder while it waits: the shell goes up immediately,
// says what it is checking, and the two panels fill in. "Loading the corpus…" on a page about a
// credential is a frame that tells the reader nothing and looks broken.
async function accountView() {
  await health();
  document.title = 'Credential — Trigon';

  const held = el('div', {}, el('p', { class: 'empty', text: 'checking what this browser holds…' }));
  const form = el('div', {});
  view.replaceChildren(
    el('p', {}, el('a', { href: '/', text: '← the corpus' })),
    el('div', { class: 'verdict-head' },
      el('h1', { text: 'Your credential' }),
      el('p', { class: 'purl', text: 'Reading this site needs nothing. Asking it to spend a build needs a token.' })),
    el('section', { class: 'panel' }, el('h2', { text: 'What you hold' }), held),
    el('section', { class: 'panel' }, el('h2', { text: 'Sign in' }), form),
  );

  await me(true);
  paintMode();

  held.replaceChildren(
    ME?.principal
      ? el('dl', { class: 'kv' },
          kv('principal', ME.principal),
          kv('name', ME.name),
          kv('may', ME.scopes.length ? ME.scopes.join(', ') : el('span', { class: 'empty', text: 'read only' })),
          kv('quota', `${ME.daily_quota} rebuild(s) a day`))
      : el('p', { class: 'empty', text: ME?.detail || 'Nothing. You are reading anonymously.' }),
  );

  const input = el('input', {
    type: 'password',
    placeholder: 'paste a token',
    'aria-label': 'Your token',
    id: 'token',
  });
  const save = async () => {
    TOKEN.set(input.value.trim() || null);
    input.value = '';
    accountView();
  };
  form.replaceChildren(
    el('div', { class: 'filters' },
      input,
      el('button', { class: 'chip', onclick: save, text: 'save' }),
      ME?.principal
        ? el('button', { class: 'chip', onclick: () => { TOKEN.set(null); accountView(); }, text: 'forget it' })
        : null),
    el('p', { class: 'note' },
      'Kept in this browser only. It never reaches another origin, and clearing it makes you anonymous again. ',
      'An operator issues one with ', el('code', { text: 'trigon grant' }), '.'),
  );
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

/* ---- what the comparison found ------------------------------------------ */

// The states a member can be in, in the words a reader needs and in the verdict palette. `watch`
// uses the same colours for the same meanings, so somebody who has seen one surface does not have
// to relearn the other.
const MEMBER_STATE = {
  differs: ['differs', 'var(--fail)', 'The two copies are not the same, and no pass accounted for it.'],
  normalized: ['stabilized out', 'var(--caveat)', 'The two copies differed and a named pass removed every way in which they did.'],
  identical: ['identical', 'var(--ok)', 'Byte for byte what was published.'],
  only_upstream: ['only published', 'var(--one-side)', 'In the published artifact and not in the rebuild.'],
  only_rebuild: ['only rebuilt', 'var(--one-side)', 'The build produced this and the published artifact does not contain it.'],
};

// What each difference rule means, for the tooltip. A rule id is stable and appears in cache keys
// and cluster names, so it is shown verbatim rather than translated — the sentence is the gloss.
const DIFFERENCE_RULE = {
  body: 'The member’s own bytes differ. This is the one that is about what somebody wrote.',
  'entry:mode': 'The archive entry’s permission bits differ. The file itself may be identical.',
  'entry:size': 'The archive entry records a different size.',
  'entry:mtime': 'The archive entry’s timestamp differs — usually a build clock nobody pinned.',
  'entry:uid': 'The archive entry records a different owner id.',
  'entry:gid': 'The archive entry records a different group id.',
  'entry:zip.crc32': 'The zip entry’s checksum differs, which follows from any of the above.',
  'entry:zip.method': 'The zip entry’s compression method differs.',
  'entry:zip.external_attrs': 'The zip entry’s external attributes differ — where a unix mode is carried.',
  'entry:zip.creator_version': 'The zip entry names a different creating tool/OS.',
  'entry:zip.reader_version': 'The zip entry names a different minimum reader version.',
  'entry:zip.dos_datetime': 'The zip entry’s MS-DOS timestamp differs.',
  'entry:mtime': 'The archive entry’s timestamp differs — usually a build clock nobody pinned.',
  entry: 'Something about the archive entry differs, rather than the file it holds.',
};

// The gloss for a difference code, falling back through `entry:zip.x → entry → the raw name`.
function glossField(rule) {
  return DIFFERENCE_RULE[rule]
    || DIFFERENCE_RULE[rule.replace(/\.[^.]+$/, '')]
    || DIFFERENCE_RULE[rule.split(':')[0]]
    || 'a field of the archive entry';
}

// One field of a member and the passes that acted on it, as a list item: the code, its gloss, and
// an arrow to the pass ids that changed it. `resolved` styles the two cases — a field a pass put
// right, versus one that still differs (where an empty pass list means nothing in the set touches
// it, which is itself the finding).
function memberFieldRow(fw, resolved) {
  const passes = fw.passes || [];
  const kids = [
    el('code', { text: fw.field }),
    el('span', { class: 'note', text: ` — ${glossField(fw.field)}` }),
  ];
  if (passes.length) {
    kids.push(el('span', { class: 'by' },
      el('span', { class: 'by-arrow', text: resolved ? ' ✓ ' : ' ↳ ' }),
      ...passes.flatMap((id, i) => [
        i ? el('span', { class: 'note', text: ', ' }) : null,
        el('code', { class: 'pass', title: (STABILIZER_DOCS[id] || {}).sum || '', text: id }),
      ].filter(Boolean))));
  } else {
    kids.push(el('span', { class: 'by empty', text: ' ↳ nothing in the set addresses it' }));
  }
  return el('li', { class: resolved ? 'fw-ok' : 'fw-residual' }, ...kids);
}

// The opened member's transform, from the comparison's field-level record: reconciled on the left,
// still-differing on the right, an arrow between only when something remains. A member with only a
// left column was made byte-identical by the passes named there — including a `.dll` reconciled by
// `dotnet-il-canonical`, whose transform leaves no residual code and so was invisible before.
function memberTransform({ reconciled, residual }) {
  const rec = reconciled || [];
  const res = residual || [];
  const differs = res.length > 0;
  return el('div', { class: `reconciled-note${differs ? ' has-residual' : ''}` },
    el('p', { class: 'sentence' },
      el('strong', { text: differs ? 'Partly reconciled. ' : 'Reconciled. ' }),
      differs
        ? 'The passes normalized the fields on the left; those on the right still differ. Each field is joined to the pass that acted on it — measured, not guessed.'
        : 'Every field that differed was normalized by a pass, and the member is now byte-identical. Each field is joined to the pass that did it.'),
    el('div', { class: 'reconciled-flow' },
      el('div', { class: 'reconciled-col' },
        el('p', { class: 'reconciled-head', text: 'reconciled' }),
        rec.length
          ? el('ul', { class: 'reconciled-diffs' }, rec.map((fw) => memberFieldRow(fw, true)))
          : el('p', { class: 'note empty', text: 'nothing needed changing' })),
      differs ? el('div', { class: 'reconciled-arrow', text: '→' }) : null,
      differs
        ? el('div', { class: 'reconciled-col' },
            el('p', { class: 'reconciled-head', text: 'still differs' }),
            el('ul', { class: 'reconciled-diffs residual' }, res.map((fw) => memberFieldRow(fw, false))))
        : null));
}

const KIND_COLOUR = {
  executable: 'var(--fail)', binary: 'var(--one-side)',
  metadata: 'var(--structural)', documentation: 'var(--ok)', source: 'var(--accent)',
};

// A verdict is a walk down three questions that stops at the first one that answers. Six digests
// are unreadable; three questions with one of them marked is the same information a person can
// hold. The rungs above the answer are greyed rather than hidden — a reader's question is "why is
// this the verdict", and the answer is which of the three stopped it.
function ladderPanel(d) {
  const rows = d.ladder.map((r, i) => {
    const past = d.ladder.findIndex((x) => x.answered);
    const spent = past >= 0 && i < past;
    return el('div', { class: `rung${r.answered ? ' answered' : ''}${spent ? ' spent' : ''}` },
      el('div', { class: 'rung-q' },
        el('span', { class: 'rung-n', text: i + 1 }),
        el('span', { text: r.question })),
      r.upstream
        ? el('div', { class: 'rung-digests mono' },
            el('span', { class: r.equal ? 'ok' : 'fail', text: short(r.upstream) }),
            el('span', { class: 'dim', text: r.equal ? ' = ' : ' ≠ ' }),
            el('span', { class: r.equal ? 'ok' : 'fail', text: short(r.rebuild) }))
        : null,
      el('p', { class: 'rung-detail', text: r.detail }));
  });
  return panel('Why this is the verdict', el('div', { class: 'ladder' }, rows));
}

const short = (hex) => (hex || '').slice(0, 12);

// One bar, banded, in the order a reader needs: what still differs first, because that is the
// finding. A band of zero width is not drawn and not listed — a legend entry pointing at nothing
// invites the reader to go looking for it.
function censusPanel(d) {
  const c = d.census;
  const bands = [
    [c.differs, 'still differ', 'var(--fail)'],
    [c.only_upstream, 'only in the published artifact', 'var(--one-side)'],
    [c.only_rebuild, 'only in the rebuild', 'var(--one-side)'],
    [c.identical, 'identical as published', 'var(--ok)'],
  ].filter(([n]) => n > 0);
  const total = Math.max(1, bands.reduce((a, [n]) => a + n, 0));

  return panel('What differs', el('div', {},
    el('div', { class: 'census' }, bands.map(([n, , colour]) =>
      el('div', { class: 'census-band', style: [['width', `${(n / total) * 100}%`], ['background', colour]] }))),
    el('p', { class: 'legend' }, bands.map(([n, label, colour]) =>
      el('span', { class: 'key' },
        el('i', { style: [['background', colour]] }),
        `${n} ${label}`))),
    c.executable_differs
      ? el('p', { class: 'withheld-note' },
          el('strong', { text: `${c.executable_differs} of them are executables. ` }),
          'That is never benign: a metadata file that differs is usually a timestamp somebody forgot to pin, and a differing binary is the thing this tool exists to find.')
      : null,
    el('p', { class: 'note' },
      `${c.total} member(s) in total, compared under the `,
      el('code', { text: d.set.id }),
      ' set (',
      el('code', { class: 'dim', text: short(d.set.digest) }),
      '). A member that differed and was accounted for by a pass is counted as identical here, because after that pass it is.')));
}

// What the artifact holds. The question "what is in this package" has an answer and the site did
// not give it.
function contentsPanel(d) {
  const entries = Object.entries(d.kinds).sort((a, b) => b[1] - a[1]);
  const total = Math.max(1, entries.reduce((a, [, n]) => a + n, 0));
  return panel('What the package holds', el('div', {},
    el('div', { class: 'census' }, entries.map(([kind, n]) =>
      el('div', {
        class: 'census-band',
        title: `${n} ${kind}`,
        style: [['width', `${(n / total) * 100}%`], ['background', KIND_COLOUR[kind] || 'var(--dim)']],
      }))),
    el('p', { class: 'legend' }, entries.map(([kind, n]) =>
      el('span', { class: 'key' },
        el('i', { style: [['background', KIND_COLOUR[kind] || 'var(--dim)']] }),
        `${n} ${kind}`))),
    el('p', { class: 'note' },
      'Published ', el('strong', { text: bytes(d.upstream_bytes) }),
      ', rebuilt ', el('strong', { text: bytes(d.rebuild_bytes) }), '.')));
}

// The ledger: which passes fired, at what risk, under whose authority, and which of them hold the
// verdict below `normalized` however well the bytes agree.
// A pass's name as a button that unfolds its plain-language description in a row beneath — the
// ledger's rows and the progression's use the same one, so a pass reads the same wherever it is
// named. Returns the name to put in a cell and the hidden row to put after the row holding it.
function passUnfold(id, colspan) {
  const doc = STABILIZER_DOCS[id];
  const detail = el('tr', { class: 'pass-doc', hidden: true },
    el('td', { colspan }, doc
      ? el('div', { class: 'pass-doc-body' },
          el('p', { class: 'sentence', text: doc.sum }),
          el('p', { class: 'note', text: doc.why }))
      : el('p', { class: 'note empty', text: 'No description on file for this pass.' })));
  const name = doc
    ? el('button', {
        class: 'pass-name', type: 'button', 'aria-expanded': 'false', title: doc.sum,
        onclick: (e) => {
          const nowOpen = detail.hidden;
          detail.hidden = !nowOpen;
          e.currentTarget.setAttribute('aria-expanded', String(nowOpen));
          e.currentTarget.classList.toggle('open', nowOpen);
        },
      }, el('code', { text: id }), el('span', { class: 'info', text: 'ⓘ' }))
    : el('code', { text: id });
  return { name, detail };
}

// How the gap closed, pass by pass: the differences left after each pass of the set, from the two
// artifacts as published to the last pass. The comparison records it (or `trigon rederive` fills
// it in for a run judged before it did); the page only draws it. Explanation, never verdict — the
// recorder checks its last step against the signature the verdict was taken on, and says so here
// when it did not match.
function progressionPanel(d) {
  const title = 'How the gap closed, pass by pass';
  const p = d.progression;
  if (!p) {
    return panel(title, el('p', { class: 'note empty' },
      'This run was judged before the comparison recorded its progression. ',
      el('code', { text: 'trigon rederive' }),
      ' fills it in from the stored artifacts, for any run judged under a stabilizer set this binary still has.'));
  }
  if (p.omitted) {
    return panel(title, el('p', { class: 'note empty', text: `Not recorded for this run: ${p.omitted}.` }));
  }
  const steps = p.steps || [];
  if (steps.length <= 1) {
    return panel(title, el('p', { class: 'note' }, steps.length && steps[0].differences === 0
      ? 'Nothing to close: the two artifacts were identical as published, so no pass had a difference to remove.'
      : 'No steps were recorded.'));
  }

  const start = steps[0];
  const end = steps[steps.length - 1];
  const max = Math.max(start.differences, 1);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const rows = steps.flatMap((s, i) => {
    const prev = i ? steps[i - 1] : null;
    const removed = prev ? prev.differences - s.differences : 0;
    const idle = prev && removed === 0 && !s.closed_total && !s.opened_total;
    const unfold = s.pass ? passUnfold(s.pass, 6) : null;
    const closedRow = el('tr', { class: 'pass-doc', hidden: true },
      el('td', { colspan: 6 }, el('div', { class: 'pass-doc-body' },
        s.closed_total ? el('p', { class: 'note' }, el('strong', { text: 'Closed here: ' }),
          s.closed.map((m, j) => [j ? ', ' : '', el('code', { text: m })]),
          s.closed_total > s.closed.length ? ` and ${s.closed_total - s.closed.length} more` : '') : null,
        s.opened_total ? el('p', { class: 'note diff' }, el('strong', { text: 'Opened here, which a pass should never do: ' }),
          s.opened.map((m, j) => [j ? ', ' : '', el('code', { text: m })]),
          s.opened_total > s.opened.length ? ` and ${s.opened_total - s.opened.length} more` : '') : null)));
    const members = s.closed_total || s.opened_total
      ? el('button', {
          class: 'chip', type: 'button',
          onclick: () => { closedRow.hidden = !closedRow.hidden; },
          text: [s.closed_total ? `closed ${s.closed_total}` : null, s.opened_total ? `opened ${s.opened_total}` : null].filter(Boolean).join(' · '),
        })
      : el('span', { class: 'dim', text: '—' });
    const passCell = s.pass
      ? el('td', {}, unfold.name,
          s.fired ? null : el('span', { class: 'tag fault', title: 'This pass changed nothing on either side of this run.', text: 'did not fire' }),
          s.fired && idle ? el('span', { class: 'dim idle-why', text: ' changed only fields that already agreed' }) : null)
      : el('td', {}, el('strong', { text: 'as published' }));
    const main = el('tr', { class: idle ? 'step-idle' : '' },
      el('td', { class: 'n dim', text: i }),
      passCell,
      // Differences can rise across a step: a pass that renames members changes the paths the
      // comparator names, so a difference may be counted under a new name before a later pass
      // closes it. Shown as a rise, never folded into "0".
      el('td', { class: 'n' }, removed > 0
        ? el('span', { class: 'delta', text: `−${removed}` })
        : removed < 0
          ? el('span', { class: 'delta grew', title: 'more differences are counted after this pass than before it', text: `+${-removed}` })
          : el('span', { class: 'dim', text: prev ? '0' : '' })),
      el('td', { class: 'bar-cell' },
        el('div', { class: 'bar-track', title: `${s.differences} difference(s) left` },
          el('div', { class: 'bar-fill', style: [['width', `${(s.differences / max) * 100}%`], ['background', s.differences ? (s.bodies ? 'var(--fail)' : 'var(--caveat)') : 'var(--ok)']] }))),
      el('td', { class: 'n', text: `${s.differences} · ${s.members}` }),
      el('td', {}, members));
    return [main, unfold ? unfold.detail : null, closedRow].filter(Boolean);
  });

  const summary = end.differences === 0
    ? `As published, the two artifacts differed in ${plural(start.differences, 'way', 'ways')} across ${plural(start.members, 'member', 'members')}. Each step below is one more pass of the set; after the last, nothing is left.`
    : `As published, the two artifacts differed in ${plural(start.differences, 'way', 'ways')} across ${plural(start.members, 'member', 'members')}. After the last pass, ${plural(end.differences, 'difference remains', 'differences remain')} in ${plural(end.members, 'member', 'members')}${end.bodies ? ` — ${end.bodies} of them in a member's own bytes, which no pass in this set removed` : ''}.`;

  return panel(title, el('div', {},
    el('p', { class: 'sentence', text: summary }),
    p.consistent ? null : el('p', { class: 'withheld-note' },
      el('strong', { text: 'Not a trustworthy explanation for this run. ' }),
      'Re-applying the set one pass at a time did not end on the difference signature the verdict was taken on. The verdict is unaffected; this panel is what cannot be relied on.'),
    el('div', { class: 'table-scroll' }, el('table', { class: 'runs ledger progression' },
      el('thead', {}, el('tr', {},
        el('th', { class: 'n', text: 'step' }),
        el('th', { text: 'pass' }),
        el('th', { class: 'n', text: 'removed' }),
        el('th', { text: 'left' }),
        el('th', { class: 'n', text: 'left · members' }),
        el('th', { text: 'members' }))),
      el('tbody', {}, rows))),
    el('p', { class: 'note' },
      'Counted as the comparator names a difference: a member\'s bytes, each field of its archive entry, a member present on one side only, and the archive as a whole. An entry\'s size and checksum, and a zip member\'s mode, are left out, because serialization recomputes them from what is counted (B47). The bar is red while a member\'s own bytes still differ, amber while only packaging does.')));
}

// What crossed the network into the build, summarized from its transcript. Fetched rather than
// booted, and gated exactly as the raw transcript is: its URLs are unredacted, so a reader refused
// the transcript is refused this with the same sentence.
function networkPanel(id, entry) {
  const title = 'What crossed the network';
  if (!entry.has.network_transcript) {
    return panel(title, el('p', { class: 'note empty', text: 'This run recorded no network transcript. Absent is not empty: it means none was written, not that nothing crossed.' }));
  }
  const slot = el('div', {}, el('p', { class: 'empty', text: 'reading the transcript…' }));
  api(`/v1/runs/${encodeURIComponent(id)}/network/summary`)
    .then((s) => slot.replaceChildren(drawNetwork(s, id)))
    .catch((e) => slot.replaceChildren(e.status === 403
      ? el('p', { class: 'withheld-note' }, el('strong', { text: 'Not shown here. ' }), el('span', { text: e.message }))
      : el('p', { class: 'note empty', text: `The transcript could not be summarized: ${e.message}` })));
  return panel(title, slot);
}

// What each guard outcome means, for the legend. The mirror's own words, shortened.
const CHECKED = {
  opened: 'every member hashed and compared against the manifest',
  hashed: 'the whole body\'s digest compared, and nothing inside it',
  generated: 'composed by the mirror itself — a filtered index — so there was nothing to catch',
  unarmed: 'no guard manifest was loaded, so nothing was compared',
  partial: 'the response never finished; the bytes are what actually crossed',
};

function drawNetwork(s, id) {
  if (!s.exchanges) {
    return el('p', { class: 'note' }, s.unreadable
      ? `The transcript holds ${s.unreadable} line(s) that are not exchanges and none that are.`
      : 'The transcript was written and is empty: the build\'s egress was accounted for, and nothing crossed.');
  }
  const hostMax = Math.max(...s.hosts.map((h) => h.bytes), 1);
  const exchangeRow = (x) => el('tr', {},
    el('td', { class: 'dim', text: x.route }),
    el('td', { class: 'url-cell' }, el('code', { text: x.url })),
    el('td', { class: 'n', text: bytes(x.bytes) }),
    el('td', { class: 'dim', title: CHECKED[x.checked] || '', text: x.checked || '—' }),
    el('td', { class: 'dim mono', title: x.sha256 || '', text: x.sha256 ? x.sha256.slice(0, 12) : '—' }));
  const exchangeTable = (list) => el('div', { class: 'table-scroll' }, el('table', { class: 'runs' },
    el('thead', {}, el('tr', {},
      el('th', { text: 'route' }), el('th', { text: 'url' }), el('th', { class: 'n', text: 'bytes' }),
      el('th', { text: 'guard' }), el('th', { text: 'sha256' }))),
    el('tbody', {}, list.map(exchangeRow))));

  return el('div', {},
    el('p', { class: 'sentence' },
      `${s.exchanges} exchange(s) crossed into the build, ${bytes(s.bytes)} in all, from ${s.hosts_total} host(s).`,
      s.withheld ? ` The mirror withheld ${s.withheld} version(s) from ${s.indexes_withholding} index document(s) because they were published after the pinned moment, so the build resolved against the registry as it stood then.` : ''),
    el('div', { class: 'net-grid' },
      el('div', {},
        el('p', { class: 'reconciled-head', text: 'by route' }),
        el('ul', { class: 'assumptions' }, s.routes.map((b) =>
          el('li', {}, el('code', { text: b.name }), ` ${b.count} · ${bytes(b.bytes)}`)))),
      el('div', {},
        el('p', { class: 'reconciled-head', text: 'what the guard could do' }),
        el('ul', { class: 'assumptions' }, s.checked.map((b) =>
          el('li', {}, el('code', { text: b.name }), ` ${b.count}`,
            CHECKED[b.name] ? el('span', { class: 'note', text: ` — ${CHECKED[b.name]}` }) : null))))),
    s.unreadable ? el('p', { class: 'withheld-note', text: `${s.unreadable} line(s) of the transcript are not exchanges and are counted here rather than dropped.` }) : null,
    el('p', { class: 'reconciled-head', text: `hosts${s.hosts_total > s.hosts.length ? ` (the ${s.hosts.length} largest of ${s.hosts_total})` : ''}` }),
    el('div', { class: 'table-scroll' }, el('table', { class: 'runs ledger' },
      el('thead', {}, el('tr', {},
        el('th', { text: 'host' }), el('th', { class: 'n', text: 'exchanges' }), el('th', { text: '' }),
        el('th', { class: 'n', text: 'bytes' }), el('th', { text: 'routes' }))),
      el('tbody', {}, s.hosts.map((h) => el('tr', {},
        el('td', {}, el('code', { text: h.host })),
        el('td', { class: 'n', text: h.count }),
        el('td', { class: 'bar-cell' }, el('div', { class: 'bar-track' },
          el('div', { class: 'bar-fill', style: [['width', `${(h.bytes / hostMax) * 100}%`], ['background', 'var(--accent)']] }))),
        el('td', { class: 'n', text: bytes(h.bytes) }),
        el('td', { class: 'dim', text: h.routes.join(', ') })))))),
    s.toolchain_total ? [
      el('p', { class: 'reconciled-head', text: `toolchain${s.toolchain_total > s.toolchain.length ? ` (${s.toolchain.length} of ${s.toolchain_total})` : ''}` }),
      exchangeTable(s.toolchain),
    ] : null,
    el('p', { class: 'reconciled-head', text: 'the largest exchanges' }),
    exchangeTable(s.largest),
    el('p', { class: 'note' },
      'Every exchange is in ',
      el('a', { href: `/v1/runs/${encodeURIComponent(id)}/network`, text: 'the full transcript' }),
      ', one JSON line each.'));
}

function ledgerPanel(d) {
  if (!d.applied.length) {
    return panel('The stabilizers', el('p', { class: 'note' },
      'No pass changed anything on either side, so the two artifacts were compared exactly as published. The verdict owes nothing to normalization.'));
  }
  const max = Math.max(...d.applied.map((p) => p.entries), 1);
  // Each pass is a button that unfolds a plain-language description of what it did — so a reader
  // can tell what `dotnet-il-canonical` or `zip-time` actually changed without leaving the page.
  const rows = d.applied.flatMap((p) => {
    const { name, detail } = passUnfold(p.id, 6);
    const main = el('tr', {},
      el('td', {}, name,
        p.caps ? el('span', { class: 'tag normalized_with_caveats', text: 'caps' }) : null),
      el('td', { class: 'n', text: p.entries }),
      el('td', { class: 'bar-cell' },
        el('div', { class: 'bar-track' },
          el('div', { class: 'bar-fill', style: [['width', `${(p.entries / max) * 100}%`], ['background', RISK_COLOUR[p.risk] || 'var(--dim)']] }))),
      el('td', { class: 'dim', text: p.risk }),
      el('td', {}, p.provenance === 'builtin'
        ? el('span', { class: 'dim', text: 'builtin' })
        : el('span', { class: 'diff', text: p.who })),
      el('td', { class: 'n dim', text: p.bytes ? bytes(p.bytes) : '—' }));
    return [main, detail];
  });

  return panel('The stabilizers', el('div', {},
    el('p', { class: 'sentence' },
      'This run could reach ',
      el('strong', { text: d.ceiling.replace(/_/g, ' ') }),
      ' and no higher, whatever the bytes did.',
      d.caps.length ? '' : ' Nothing in this set holds it down.'),
    d.caps.length
      ? el('ul', { class: 'assumptions' }, d.caps.map((c) =>
          el('li', {}, el('code', { text: c.id }), el('span', { text: ` — ${c.why}` }))))
      : null,
    el('table', { class: 'runs ledger' },
      el('thead', {}, el('tr', {},
        el('th', { text: 'pass' }),
        el('th', { class: 'n', text: 'entries' }),
        el('th', { text: '' }),
        el('th', { text: 'risk' }),
        el('th', { text: 'provenance' }),
        el('th', { class: 'n', text: 'bytes' }))),
      el('tbody', {}, rows)),
    el('p', { class: 'note' },
      'Summed across both sides, which fire the same set. A cap is not a complaint about the package: it says we got there using something we will not vouch for unconditionally — a pass that rewrites content, or one a person or a model wrote rather than one compiled in. Both halves weigh the same.'),
    d.silent === null
      ? el('p', { class: 'note empty' },
          'Which passes were configured and stayed silent is not recorded. A pass finding nothing to do is evidence — an unsigned package, an archive with no timestamps — and the comparison keeps the set’s digest but not its membership, so nothing downstream can tell that from a pass that was never configured.')
      : el('p', { class: 'note' }, `Silent: ${d.silent.join(', ') || 'none'}.`)));
}

const RISK_COLOUR = {
  structural: 'var(--structural)', metadata: 'var(--ok)',
  content: 'var(--caveat)', lossy: 'var(--fail)',
};

// What each pass actually does, in the words a reader needs. `sum` is the one line; `why` says what
// it normalizes and why doing so is safe — never code, always something a build wrote around the
// code. Keyed by the id the ledger prints, so a pass with no entry simply shows none.
const STABILIZER_DOCS = {
  'tar-entry-order': { sum: 'Sorts the archive entries into a canonical order.', why: 'Two builds can lay the same files down in a different order; the order is not part of what the package means, so both are sorted the same way before comparing.' },
  'tar-time': { sum: 'Zeroes each entry’s modification time.', why: 'A build stamps every file with when it ran. That instant is not reproducible and is not content, so it is fixed to the same value on both sides.' },
  'tar-mode': { sum: 'Normalizes Unix permission bits.', why: 'The umask and tooling of the building machine leak into the mode bits; the executable bit that matters is kept, the rest normalized.' },
  'tar-owners': { sum: 'Zeroes the owning uid and gid.', why: 'Which numeric user built the package is not part of it.' },
  'tar-xattrs': { sum: 'Drops extended attributes a build tool may attach.', why: 'Filesystem xattrs (SELinux labels, provenance) travel with a build machine, not with the package.' },
  'tar-device': { sum: 'Zeroes device major/minor numbers on special entries.', why: 'A device number is a property of the machine, not the archive.' },
  'zip-entry-order': { sum: 'Sorts zip entries into a canonical order.', why: 'The order a zip lists its files in is the writer’s choice, not content; both sides are sorted the same way.' },
  'zip-time': { sum: 'Zeroes each zip entry’s timestamp.', why: 'The DOS date/time a zip records is when the build ran, which is not reproducible and not content.' },
  'zip-versions': { sum: 'Normalizes the “version made by / needed to extract” fields.', why: 'These name which tool and OS wrote the zip, not what is inside it.' },
  'zip-misc': { sum: 'Normalizes assorted zip header fields that vary by writer.', why: 'External attributes and general-purpose flags differ between zip libraries without changing a byte of the files.' },
  'zip-compression': { sum: 'Re-expresses every entry at one canonical compression.', why: 'Deflate level is a choice of the writer; the uncompressed bytes are what matter, so two zips of identical files match whatever level each used.' },
  'gzip-meta': { sum: 'Zeroes the gzip header’s timestamp, name and OS byte.', why: 'The gzip wrapper records when and where it ran; the compressed content underneath is unchanged.' },
  'cargo-vcs-hash': { sum: 'Normalizes the git commit in a crate’s .cargo_vcs_info.json.', why: 'The recorded commit says where the source lives, not what it is — and a rebuild from a tag resolves it differently. Content risk: it edits a file the package ships.' },
  'npm-install-fields': { sum: 'Drops npm’s install-time bookkeeping fields.', why: 'A tarball’s recorded integrity/resolved/from fields say where npm fetched it, not what is in it.' },
  'nupkg-portable-folder-name': { sum: 'Renames a portable-framework lib folder to a canonical spelling.', why: 'Tooling writes `portable-net45+win8` and its permutations inconsistently; the folder’s meaning is the same however the monikers are ordered.' },
  'nupkg-signature': { sum: 'Removes a NuGet package’s author signature (.signature.p7s).', why: 'A signature is made with a private key the rebuild does not have, over the very bytes being rebuilt. Structural: a whole member is dropped.' },
  'nupkg-packaging-names': { sum: 'Normalizes the random GUID names OPC packaging invents.', why: 'The `.psmdcp` file and its relationship entry are named after a fresh GUID on every pack; nothing depends on the name.' },
  'nupkg-packager-version': { sum: 'Zeroes the packaging-tool version in the .nuspec’s psmdcp.', why: 'Which NuGet version wrote the package is provenance, not content.' },
  'nupkg-text-eol': { sum: 'Normalizes line endings in the package’s text files.', why: 'CRLF vs LF is a checkout and platform artifact; the text is the same either way. Content risk: it rewrites shipped bytes.' },
  'nupkg-doc-member-order': { sum: 'Sorts the members of an XML documentation file.', why: 'The compiler may emit `<member>` entries in any order; sorting them makes two docs of the same API match. Structural.' },
  'dotnet-assembly-identity': { sum: 'Zeroes a .NET assembly’s build and signing identity.', why: 'The strong-name signature (a key we do not have), the module MVID (a per-compilation GUID), the PE timestamp and checksum, and the debug-directory data — none is code, all are stamps a build writes around it.' },
  'dotnet-il-canonical': { sum: 'Compares a managed assembly by its code, not its byte layout.', why: 'It reads the assembly’s own tables and keeps every method’s name, signature and IL, resolved through the heaps to values — so two assemblies built from the same source match even when SourceLink, a source-generator’s document order or a shifted heap laid their metadata and embedded PDB out differently. Lossy: it drops resources, attributes and field data, so a match it makes is caveated, and a real code change still shows.' },
  'nupkg-repository-branch': { sum: 'Drops the <repository branch=…> git ref from the .nuspec.', why: 'That names the tag or branch the publisher built from, which a detached-commit checkout cannot reproduce. The commit — the identity — is kept.' },
  'nupkg-readme-markers': { sum: 'Strips NuGetizer’s <!-- include … --> readme markers.', why: 'These are assembly directives NuGetizer leaves in the readme, spelled a hair differently once a remote include is neutralized for an offline build; the text a reader sees is unchanged. Content risk.' },
  'pyc-header': { sum: 'Zeroes the source mtime in a .pyc header.', why: 'A compiled Python file stamps when its .py was last modified, for cache invalidation — not part of the bytecode.' },
  'wheel-direct-url': { sum: 'Drops direct_url.json from a wheel.', why: 'It records the URL or path pip installed from, which is about the install, not the package.' },
  'wheel-metadata-eol': { sum: 'Normalizes line endings in a wheel’s METADATA and RECORD.', why: 'CRLF vs LF in the metadata is a platform artifact. Content risk.' },
  'wheel-record': { sum: 'Rebuilds the wheel’s RECORD manifest after the other passes.', why: 'RECORD lists every file and its hash; the passes above change some, so it is regenerated last so it still describes the package.' },
  'wheel-direct-url-drop': { sum: 'Drops direct_url.json from a wheel.', why: 'Records where pip installed from, not what is in the package.' },
  'gem-exclude-checksums': { sum: 'Drops a gem’s checksums.yaml.gz.', why: 'It is a hash of the gem’s other members and is re-derivable from them, so it carries nothing new.' },
  'gem-exclude-signatures': { sum: 'Drops a gem’s signature files.', why: 'Made with a private key the rebuild does not have.' },
  'gem-metadata-cert-chain': { sum: 'Zeroes the signing certificate chain in a gem’s metadata.', why: 'The signer’s certificate is identity, not content.' },
  'gem-metadata-date': { sum: 'Zeroes the build date in a gem’s metadata.', why: 'When the gem was built is not part of it.' },
  'gem-metadata-rubygems-version': { sum: 'Normalizes the RubyGems tool version in a gem’s metadata.', why: 'Which packaging version wrote the gem is provenance.' },
};

// Field-level attribution is no longer inferred here: the comparison records which pass changed
// which field of which member (`member.reconciled` / `member.residual`), so the transform is read
// off ground truth in `memberTransform` rather than guessed from the file's name.

// Every member, most interesting first. A hundred identical members must not bury the ten that
// differ, and a list capped at five hundred that sorted by path would cap away exactly the rows
// somebody came to read.
function membersPanel(d, runId) {
  const rows = d.members.flatMap((m) => {
    const [label, colour, why] = MEMBER_STATE[m.status] || [m.status, 'var(--dim)', ''];
    // Ground truth from the comparison: `reconciled` is the fields a pass changed that no longer
    // differ, each with the pass that did it; `residual` is what still differs, each with the pass
    // that tried (or nothing). Either makes the member worth opening — a member a pass touched has
    // a story even when it ended identical (Moq's DLLs, reconciled by `dotnet-il-canonical`).
    const reconciled = (m.reconciled && m.reconciled.length) || (m.residual && m.residual.length)
      ? { reconciled: m.reconciled || [], residual: m.residual || [] }
      : null;
    const worth = m.status !== 'identical' || !!reconciled;
    const slot = el('td', { colspan: 6, class: 'member-slot' });
    const open = () => {
      rememberOpen(m.path);
      openMember(runId, m.path, slot, { reconciled });
    };
    // Entered on a link to this member. The server has usually already put the panel in the
    // document, in which case it is drawn here with no request at all — see `BOOT.member`. Where it
    // has not (an anonymous reader, whose principal may not see a member's bytes; or a copy served
    // from a CDN), this falls through to the fetch and the refusal explains itself.
    if (worth && OPEN_ON_LOAD && OPEN_ON_LOAD.member === m.path) {
      const want = OPEN_ON_LOAD;
      const booted = BOOT?.member && BOOT.member.member?.path === m.path;
      if (booted) {
        drawMember(runId, m.path, slot, { view: want.view || BOOT.member.view || undefined }, BOOT.member.member);
      } else {
        queueMicrotask(() => openMember(runId, m.path, slot, { view: want.view }));
      }
    }
    // A member a pass fully reconciled (touched, nothing left differing) gets the check marker;
    // one that still differs does not, even where a pass acted on it.
    const fullyReconciled = reconciled && !(m.residual && m.residual.length);
    const memberTitle = !reconciled
      ? 'open this member'
      : fullyReconciled
        ? 'a pass changed this and reconciled it — open to see what it did'
        : 'a pass acted on this and it still differs — open to see the split';
    return [el('tr', { class: [worth ? 'openable' : '', fullyReconciled ? 'reconciled' : ''].filter(Boolean).join(' ') },
      el('td', { class: 'url' }, worth
        ? el('button', { class: 'member-link', onclick: open, title: memberTitle, text: m.path })
        : el('code', { text: m.path })),
      el('td', {}, el('span', { class: 'member-state', title: why },
        el('i', { style: [['background', colour]] }), label)),
      // The residual codes — what still differs after stabilization. An identical member with an
      // `entry:` rule here has bytes that match and a frame field the passes left; open it to see
      // that split, and which pass, if any, acted on each field.
      el('td', { class: 'opt' }, m.differences.length
        ? m.differences.map((r) => el('span', {
            class: 'rule',
            title: DIFFERENCE_RULE[r] || DIFFERENCE_RULE[r.split(':')[0]] || r,
            text: r,
          }))
        : el('span', { class: 'empty', text: '—' })),
      el('td', { class: 'opt dim', text: m.kind }),
      el('td', { class: 'n dim', text: m.upstream_bytes === null || m.upstream_bytes === undefined ? '—' : bytes(m.upstream_bytes) }),
      el('td', { class: 'n dim', text: m.rebuild_bytes === null || m.rebuild_bytes === undefined ? '—' : bytes(m.rebuild_bytes) })),
      worth ? el('tr', { class: 'member-row' }, slot) : null,
    ].filter(Boolean);
  });
  return panel('Member by member', el('div', {},
    el('table', { class: 'runs members' },
      el('thead', {}, el('tr', {},
        el('th', { text: 'member' }),
        el('th', { text: 'state' }),
        el('th', { class: 'opt', text: 'what differed' }),
        el('th', { class: 'opt', text: 'kind' }),
        el('th', { class: 'n', text: 'published' }),
        el('th', { class: 'n', text: 'rebuilt' }))),
      el('tbody', {}, rows)),
    el('p', { class: 'note' },
      el('strong', { text: 'What differed' }),
      ' is what the comparator saw ',
      el('em', { text: 'before' }),
      ' any pass ran. A member listed as identical with an ',
      el('code', { text: 'entry:' }),
      ' rule beside it is the case worth reading twice: the file is byte for byte what was published and its archive entry was not, so the difference was about how it was packed and a pass removed it.'),
    d.members_omitted
      ? el('p', { class: 'withheld-note', text: `${d.members_omitted} further member(s) are not listed. The list is capped so one request against a very large artifact cannot become a very large response; the full comparison is linked below.` })
      : null));
}

// What the comparison noticed, whether or not it changed the verdict. `ExecutableContentDiffers`
// carries the doc comment "Never benign" and `is_noteworthy` says such a note "should reach a human
// even when the verdict is a clean match" — so it reaches one here rather than living in a blob.
function notesPanel(d) {
  if (!d.notes.length) {
    return panel('What the comparison noticed', el('p', { class: 'note' },
      'Nothing beyond the verdict. Not an empty section by accident: parse limits, malformed entries and executables whose content differs all leave a note here, and none did.'));
  }
  return panel('What the comparison noticed', el('div', {},
    el('table', { class: 'runs' },
      el('thead', {}, el('tr', {},
        el('th', { text: 'what' }),
        el('th', { class: 'n', text: 'count' }),
        el('th', { text: 'where' }))),
      el('tbody', {}, d.notes.map((n) => el('tr', {},
        el('td', {},
          el('code', { text: n.code }),
          n.noteworthy ? el('span', { class: 'tag divergent', text: 'reaches a human' }) : null),
        el('td', { class: 'n', text: n.count }),
        el('td', { class: 'url dim' },
          el('code', { text: n.paths.length ? n.paths.slice(0, 3).join(', ') + (n.paths.length > 3 ? ` +${n.paths.length - 3}` : '') : '—' })))))),
    el('p', { class: 'note' },
      'A note marked ', el('span', { class: 'tag divergent', text: 'reaches a human' }),
      ' is one the type itself documents as never benign — it is shown whatever the verdict says.')));
}

/* ---- one member, opened ------------------------------------------------- */

// `?member=<path>&view=hex` on a run page. Read once at navigation rather than watched, so a
// reader who opens a second member does not find the first one reopening under them.
//
// **A query, not a fragment.** It was a fragment, which is the natural home for in-page state and
// exactly wrong for a link somebody sends: a fragment never reaches the server, so the one thing a
// deep link most wants rendered was the one thing the document could not carry. The old form is
// still read, because links to it exist and a link that silently does nothing is worse than one
// extra line here.
let OPEN_ON_LOAD = null;
function readOpenRequest() {
  try {
    const q = new URLSearchParams(location.search);
    const f = new URLSearchParams(location.hash.replace(/^#/, ''));
    const member = q.get('member') || f.get('member');
    OPEN_ON_LOAD = member
      ? { member, view: q.get('view') || f.get('view') || undefined }
      : null;
  } catch {
    OPEN_ON_LOAD = null;
  }
}

// Put the open member in the address bar, where the server will see it next time.
function rememberOpen(path, view) {
  const q = new URLSearchParams({ member: path });
  if (view) q.set('view', view);
  history.replaceState({}, '', `${location.pathname}?${q}`);
}


const hx = (s, i) => s.slice(i * 2, i * 2 + 2);
const printable = (byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '·');

// A conventional dump, two sides, with differing bytes marked on both. Rows of sixteen because
// that is what every other hex viewer does and a reader should not have to count.
function hexRows(region) {
  const up = region.upstream || '';
  const rb = region.rebuild || '';
  const len = Math.max(up.length, rb.length) / 2;
  const rows = [];
  for (let r = 0; r * 16 < len; r++) {
    const base = r * 16;
    const cells = (src, other) => {
      const out = [];
      for (let i = 0; i < 16; i++) {
        const k = base + i;
        const a = hx(src, k);
        const b = hx(other, k);
        out.push(el('span', {
          class: `hb${a && a !== b ? ' differs' : ''}${a ? '' : ' absent'}`,
          text: a || '  ',
        }));
      }
      return out;
    };
    const ascii = (src, other) => {
      const out = [];
      for (let i = 0; i < 16; i++) {
        const k = base + i;
        const a = hx(src, k);
        const b = hx(other, k);
        out.push(el('span', {
          class: `hc${a && a !== b ? ' differs' : ''}`,
          text: a ? printable(parseInt(a, 16)) : ' ',
        }));
      }
      return out;
    };
    rows.push(el('div', { class: 'hex-row' },
      el('span', { class: 'hex-off', text: (region.offset + base).toString(16).padStart(8, '0') }),
      el('span', { class: 'hex-side' }, cells(up, rb), el('span', { class: 'hex-ascii' }, ascii(up, rb))),
      el('span', { class: 'hex-side' }, cells(rb, up), el('span', { class: 'hex-ascii' }, ascii(rb, up)))));
  }
  return rows;
}

function hexView(d, reload) {
  const h = d.hex;
  if (!h || !h.regions.length) {
    return el('p', { class: 'empty', text: 'Nothing to show: both copies are empty.' });
  }
  const shown = h.regions.reduce((a, r) => a + Math.max(r.upstream.length, r.rebuild.length) / 2, 0);
  const last = h.regions[h.regions.length - 1];
  const nextOffset = last.offset + Math.max(last.upstream.length, last.rebuild.length) / 2;
  const longest = Math.max(h.upstream_bytes, h.rebuild_bytes);

  return el('div', {},
    el('p', { class: 'note' },
      h.first_difference === null
        ? 'Only one side has this member, so there is nothing to compare it against. '
        : `First difference at offset ${h.first_difference} (0x${h.first_difference.toString(16)}). `,
      h.differing_bytes
        ? `${bytes(h.differing_bytes)} of this member differ, across ${h.differing_runs} run(s); showing ${bytes(shown)}. `
        : 'The two copies are byte for byte the same. ',
      h.regions_omitted ? `${h.regions_omitted} further region(s) are not shown. ` : ''),
    el('div', { class: 'hex' },
      el('div', { class: 'hex-head' },
        el('span', { class: 'hex-off', text: 'offset' }),
        el('span', { class: 'hex-side', text: 'as published' }),
        el('span', { class: 'hex-side', text: 'as rebuilt' })),
      h.regions.map((r, i) => [
        i ? el('div', { class: 'hex-gap', text: `… ${bytes(r.offset - (h.regions[i - 1].offset + Math.max(h.regions[i - 1].upstream.length, h.regions[i - 1].rebuild.length) / 2))} not shown …` }) : null,
        hexRows(r),
      ])),
    // Paging, because a file that differs throughout has more of it than any window can hold and
    // the alternative is downloading both copies to look at byte 300,000.
    longest > shown
      ? el('p', { class: 'filters' },
          el('button', {
            class: 'chip',
            onclick: () => reload({ offset: Math.max(0, last.offset - 8192) }),
            text: '← earlier',
          }),
          nextOffset < longest
            ? el('button', { class: 'chip', onclick: () => reload({ offset: nextOffset }), text: 'later →' })
            : null,
          el('button', { class: 'chip', onclick: () => reload({}), text: 'back to the differences' }))
      : null);
}

function textView(d) {
  const t = d.text;
  if (!t) return null;
  if (!t.hunks.length) {
    return el('p', { class: 'note' },
      'No line differs. The two copies are not byte for byte identical — see the hex view — so what differs is line endings, trailing whitespace, or a final newline.');
  }
  return el('div', {},
    t.unaligned
      ? el('p', { class: 'withheld-note' },
          el('strong', { text: 'Too much changed to align line by line. ' }),
          'Everything below is reported as removed and re-added, which is what a wholesale rewrite looks like — and also what a file we declined to align looks like. This is the second.')
      : null,
    t.truncated ? el('p', { class: 'note empty', text: t.truncated }) : null,
    el('div', { class: 'diff' }, t.hunks.map((h) => [
      el('div', { class: 'hunk-head', text: `@@ published ${h.upstream_start}, rebuilt ${h.rebuild_start} @@` }),
      h.lines.map((l) => el('div', { class: `dl ${l.kind}` },
        el('span', { class: 'dm', text: l.kind === 'removed' ? '−' : l.kind === 'added' ? '+' : ' ' }),
        el('span', { class: 'dt', text: l.text || ' ' }))),
    ])),
    t.lines_omitted
      ? el('p', { class: 'withheld-note' },
          el('strong', { text: `${t.lines_omitted.toLocaleString()} further changed line(s) are not shown. ` }),
          'The rendered diff stops at ', el('strong', { text: t.lines_shown.toLocaleString() }),
          ' line(s). A file that differs this widely is read by downloading both copies, not by scrolling; '
            + 'both are on the raw links above.')
      : null,
    el('p', { class: 'note' },
      el('strong', { text: '−' }), ' is the published copy, ', el('strong', { text: '+' }), ' the rebuilt one. ',
      `${t.upstream_lines} line(s) published, ${t.rebuild_lines} rebuilt.`));
}

// Opened inline under the row rather than on its own page: a reader comparing several members is
// comparing them, and a route change loses the table they were reading.
async function openMember(runId, path, slot, state) {
  slot.replaceChildren(el('p', { class: 'empty', text: 'reading both copies…' }));
  let d;
  try {
    const q = new URLSearchParams({ path });
    if (state.offset !== undefined) q.set('offset', String(state.offset));
    d = await api(`/v1/runs/${encodeURIComponent(runId)}/member?${q}`);
  } catch (e) {
    slot.replaceChildren(el('div', { class: 'withheld-note' },
      el('strong', { text: 'Not shown. ' }), el('span', { text: e.message })));
    return;
  }
  drawMember(runId, path, slot, state, d);
}

// The rendering half, separate from the fetching half, so a panel the server already put in the
// document is drawn with no request at all. Paging and the view toggle go back through
// `openMember`, because those ask for something the boot did not carry.
function drawMember(runId, path, slot, state, d) {
  const reload = (next) => openMember(runId, path, slot, { ...state, ...next, offset: next.offset });
  const wantHex = state.view ? state.view === 'hex' : (d.binary && !d.decompiled);
  const raw = (side) => `/v1/runs/${encodeURIComponent(runId)}/member/raw?` +
    new URLSearchParams({ path, side });

  const tab = (label, key, enabled) => el('button', {
    class: 'chip',
    'aria-pressed': (key === 'hex') === wantHex,
    disabled: !enabled,
    onclick: () => {
      rememberOpen(path, key);
      openMember(runId, path, slot, { ...state, view: key });
    },
    text: label,
  });

  slot.replaceChildren(el('div', { class: 'member-open' },
    el('div', { class: 'filters' },
      tab(d.decompiled ? 'C# (decompiled)' : 'text', 'text', !!d.text),
      tab('hex', 'hex', true),
      el('span', { class: 'spacer' }),
      d.in_upstream ? el('a', { class: 'chip', href: raw('upstream'), text: '↓ published' }) : null,
      d.in_rebuild ? el('a', { class: 'chip', href: raw('rebuild'), text: '↓ rebuilt' }) : null,
      el('button', {
        class: 'chip',
        onclick: () => {
          slot.replaceChildren();
          history.replaceState({}, '', location.pathname);
        },
        text: 'close',
      })),

    // How this member was transformed, from the comparison's own record: on the left the fields a
    // pass changed and reconciled, on the right the fields that still differ — each joined to the
    // pass that acted on it. Ground truth, not inference: the stabilizer measured what it changed.
    state.reconciled
      ? memberTransform(state.reconciled)
      : null,

    !d.in_upstream || !d.in_rebuild
      ? el('p', { class: 'withheld-note' },
          el('strong', { text: d.in_upstream ? 'Only the published artifact has this. ' : 'Only the rebuild has this. ' }),
          d.in_upstream
            ? 'The build did not produce it, so there is nothing to compare against — what is below is the published file itself.'
            : 'The published artifact does not contain it, so the build produced something that was never shipped. What is below is that file.')
      : null,

    d.decompiled
      ? el('p', { class: 'note empty' },
          'The text view is C# decompiled by ILSpy — a reading of the assembly, not its bytes (those are the hex view). ILSpy hides most compiler codegen, so an empty diff means it found no source-level difference; weigh it with the census, it is not proof the sources match.')
      : (d.binary && !state.view
          ? el('p', { class: 'note empty' },
              `Opened as hex: ${d.binary_because}. The text view is off for this member because rendering these bytes as lines would invent structure they do not have.`)
          : null),

    d.unavailable ? el('p', { class: 'withheld-note', text: d.unavailable }) : null,

    wantHex ? hexView(d, reload) : (textView(d) || hexView(d, reload)),

    el('p', { class: 'note empty' },
      'Both copies as they were published and built, before any stabilizer ran. What the passes would have done to them is in the ledger above.')));
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

  // The comparison goes in a slot rather than in front of the paint. See `fillLater`.
  const comparison = el('div', {});
  if (entry.has.comparison) {
    comparison.replaceChildren(
      panel('What differs', el('p', { class: 'empty', text: 'reading the comparison…' })),
    );
    // The server puts the comparison in the document when the page is entered directly and it is
    // small enough to be worth carrying. Spent once: a second run reached by clicking is a fetch,
    // because the island describes the entry point and nothing else.
    const bootedDiff = BOOT?.diff && !DIFF_BOOT_SPENT;
    DIFF_BOOT_SPENT = true;
    fillLater(
      comparison,
      bootedDiff
        ? Promise.resolve(BOOT.diff)
        : api(`/v1/runs/${encodeURIComponent(id)}/diff`).catch(() => null),
      (d) => [
        ladderPanel(d),
        censusPanel(d),
        contentsPanel(d),
        ledgerPanel(d),
        progressionPanel(d),
        membersPanel(d, id),
        notesPanel(d),
      ],
      () => panel('What differs', el('p', { class: 'note empty' },
        'The comparison could not be rendered. The raw blob is still linked below — a rendering that fails should cost you a page, not the evidence.')),
    );
  }

  const panels = [
    comparison,

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

    record.diff_opinion ? panel('What a model made of the diff', el('div', {},
      el('dl', { class: 'kv' },
        kv('its reading', el('span', { class: 'tag', text: record.diff_opinion.verdict })),
        kv('because', record.diff_opinion.reason || '—'),
        kv('who read it', el('span', { class: 'mono', text: record.diff_opinion.model })),
        kv('shown', `${record.diff_opinion.members_shown} of ${record.diff_opinion.members_differing} differing member(s)`),
      ),
      el('p', { class: 'note empty' },
        'An opinion, not part of the verdict. The comparison above was decided from bytes alone; this row exists so a reader triaging divergences knows which ones a model thought were semantic noise.'))) : null,

    record.assumptions?.length ? panel('What this had to assume', el('div', {},
      el('ul', { class: 'assumptions' }, record.assumptions.map((a) => el('li', { text: a }))),
      el('p', { class: 'note empty' },
        'A verdict reached under assumptions is a different claim from one reached under none, which is why they are listed beside it rather than folded into it.'))) : null,

    record.guard_trips?.length ? panel('Why this is void', el('div', {},
      el('ul', { class: 'assumptions' }, record.guard_trips.map((g) => el('li', { text: g }))),
      el('p', { class: 'note empty' },
        'The artifact under test reached the build over the network. Whatever came out may be perfectly honest and we cannot tell, which is exactly what void means.'))) : null,

    panel('What it cost', costs(record)),

    networkPanel(id, entry),

    panel('The evidence, as stored', el('div', {},
      el('p', { class: 'note' },
        // A run that reached no verdict has no panels above this one, so the sentence that
        // describes them would be describing nothing.
        entry.has.comparison
          ? 'The bytes the panels above were rendered from. A third party re-derives a verdict from these, not from a page: '
          : 'What this run left behind. A third party re-derives a verdict from these rather than from a page: ',
        el('code', { text: 'trigon verify-attestation --rerun-comparison' }),
        '.'),
      el('div', { class: 'evidence' },
      evidenceLink('the comparison', `/v1/runs/${id}/comparison`, entry.has.comparison, 'The full member-by-member comparison, with every stabilizer that fired.'),
      evidenceLink('the build log', `/v1/runs/${id}/log`, entry.has.build_log, 'Unredacted, so it is served to a principal and not to the internet.'),
      evidenceLink('what crossed the network', `/v1/runs/${id}/network`, entry.has.network_transcript, 'Every request the build made, as the mirror saw it.'),
      evidenceLink('the signed statement', `/v1/runs/${id}/attestation`, entry.attested, 'The product: a claim re-derived from the bytes before it was signed.'),
      ))),

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
  provenance_unknown: 'this record does not say whether a hand-written or model-written stabilizer was applied, so one of the five safeguards cannot be checked. An accusation is not published on a safeguard nobody evaluated.',
  image_derived_outside_boundary: 'this run built its own base image, which spends network outside the boundary the rest of the run accounts for. The build ran at the tier it claims; the environment it ran in was assembled without that account.',
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

/* ---- the lockfile check, the clusters, and the fleet -------------------- */

/// The five statuses, in the order the summary prints them and with the glyph each carries.
/// `never checked` last and never omitted: a blank row reads as green.
const CHECK_COLOUR = {
  reproduced: 'var(--ok)',
  caveats: 'var(--caveat)',
  divergent: 'var(--divergent, var(--one-side))',
  unsupported: 'var(--void)',
  // Deliberately not a neutral wash. The whole point of the row is that it must not read as fine.
  'never checked': 'var(--faint)',
};

const CHECK_ROWS = [
  ['reproduced', '✔', 'reproduced'],
  ['caveats', '◐', 'normalized_with_caveats'],
  ['divergent', '✖', 'divergent'],
  ['unsupported', '⊘', 'none'],
  ['never checked', '?', 'none'],
];

async function checkView() {
  await health();
  document.title = 'Check a lockfile — Trigon';

  const out = el('div', {});
  const box = el('textarea', {
    class: 'lockbox',
    rows: '10',
    spellcheck: 'false',
    placeholder:
      'Paste a package-lock.json, a requirements.txt, or an SPDX SBOM.\n'
      + 'Nothing is stored: the file is read, matched against the corpus, and forgotten.',
  });

  async function run() {
    const body = box.value.trim();
    if (!body) {
      out.replaceChildren(el('p', { class: 'empty', text: 'Nothing pasted yet.' }));
      return;
    }
    // Paint the wait, because this one really is a round trip the reader asked for by clicking.
    out.replaceChildren(el('p', { class: 'empty', text: 'reading it…' }));
    let d;
    try {
      d = await api('/v1/check', { method: 'POST', body, raw: true });
    } catch (e) {
      out.replaceChildren(el('div', { class: 'withheld-note' },
        el('strong', { text: 'Not read. ' }), el('span', { text: e.message })));
      return;
    }
    drawCheck(out, d);
  }

  view.replaceChildren(
    el('p', {}, el('a', { href: '/', text: '← the corpus' })),
    el('div', { class: 'verdict-head' },
      el('h1', { text: 'Check a lockfile' }),
      el('p', { class: 'purl', text: 'The one view that starts from something you already have.' })),
    el('section', { class: 'panel' }, box,
      el('p', {}, el('button', { class: 'chip', onclick: run, text: 'check it' }))),
    out,
  );
}

function drawCheck(slot, d) {
  const total = d.packages || 0;
  const summary = CHECK_ROWS.map(([key, glyph, tag]) => {
    const n = d.tally[key] || 0;
    const share = total ? Math.round((n * 100) / total) : 0;
    return el('tr', {},
      el('td', { text: glyph }),
      el('td', {}, el('span', { class: `tag ${tag}`, text: key })),
      el('td', { class: 'n', text: String(n) }),
      el('td', {}, bar(share, CHECK_COLOUR[key])));
  });

  // Everything that is not a clean reproduction, which is what somebody came here to find.
  const notable = d.results.filter((r) => r.status !== 'reproduced');
  slot.replaceChildren(
    el('section', { class: 'panel' },
      el('h2', { text: `${total} package(s)` }),
      el('table', { class: 'runs' }, el('tbody', {}, summary)),
      el('p', { class: 'note' },
        el('strong', { text: 'never checked' }), ' counts packages with no run, and ',
        el('strong', { text: 'unsupported' }), ' runs that reached no verdict. Neither is a '
        + 'statement about the package, and neither is summed with the three above them — which '
        + 'is why there is no single percentage here.')),
    notable.length
      ? el('table', { class: 'runs' },
          el('thead', {}, el('tr', {},
            el('th', { text: 'package' }),
            el('th', { class: 'opt', text: 'version' }),
            el('th', { text: 'status' }),
            el('th', { text: 'why' }))),
          el('tbody', {}, notable.map((r) => el('tr', {},
            el('td', { class: 'pkg' }, r.run
              ? el('a', { href: `/runs/${encodeURIComponent(r.run)}`, text: r.name })
              : el('span', { text: r.name })),
            el('td', { class: 'opt', text: r.version }),
            el('td', {}, el('span', {
              class: `tag ${CHECK_ROWS.find(([k]) => k === r.status)?.[2] || 'none'}`,
              text: r.status,
            })),
            el('td', { class: 'note', text: r.detail || '' })))))
      : el('p', { class: 'empty', text: 'Every package in this file reproduced.' }),
  );
}

/// One share bar, using the same track and fill the corpus bars use.
///
/// `style` goes through `el`'s array form, which sets properties through the CSSOM: the page's own
/// CSP is `style-src 'self'`, and that blocks the `style` *attribute*, not just a stylesheet.
function bar(pct, colour) {
  return el('div', { class: 'bar-track' },
    el('div', {
      class: 'bar-fill',
      style: [['width', `${pct}%`], ['background', colour || 'var(--dim)']],
    }));
}

async function clustersView() {
  await health();
  document.title = 'Failure clusters — Trigon';
  let d;
  try {
    d = await api('/v1/clusters');
  } catch (e) {
    view.replaceChildren(
      el('p', {}, el('a', { href: '/', text: '← the corpus' })),
      el('div', { class: 'verdict-head' }, el('h1', { text: 'Failure clusters' })),
      el('div', { class: 'withheld-note' },
        el('strong', { text: 'Not shown. ' }), el('span', { text: e.message })));
    return;
  }

  const rows = d.clusters.map((c) => el('tr', {},
    el('td', { class: 'n', text: String(c.count) }),
    el('td', { class: 'pkg', text: c.key }),
    el('td', { class: 'opt', text: c.ecosystems.join(', ') }),
    el('td', { class: 'opt', text: (c.last_seen || '').slice(0, 10) }),
    el('td', {}, ...c.runs.slice(0, 3).map((id, i) => el('span', {},
      i ? ', ' : '',
      el('a', { href: `/runs/${encodeURIComponent(id)}`, text: id.slice(-8) })))),
  ));

  view.replaceChildren(
    el('p', {}, el('a', { href: '/', text: '← the corpus' })),
    el('div', { class: 'verdict-head' },
      el('h1', { text: 'Failure clusters' }),
      el('p', { class: 'purl', text: 'Grouped by the signature that keys the repair cache, so a cluster is the set of runs one fix would move.' })),
    rows.length
      ? el('table', { class: 'runs' },
          el('thead', {}, el('tr', {},
            el('th', { class: 'n', text: 'runs' }),
            el('th', { text: 'signature' }),
            el('th', { class: 'opt', text: 'ecosystems' }),
            el('th', { class: 'opt', text: 'last seen' }),
            el('th', { text: 'examples' }))),
          el('tbody', {}, rows))
      : el('p', { class: 'empty', text: 'No run in this corpus carries a failure signature.' }),
  );
}

async function fleetView() {
  await health();
  document.title = 'Fleet — Trigon';
  const d = await api('/v1/fleet');

  const q = d.queue;
  const workers = (q && q.workers) || [];
  const queuePanel = !q
    ? el('p', { class: 'empty', text: 'This instance serves a corpus read from storage and has no queue.' })
    : el('div', {},
        el('h2', { text: 'Depth' }),
        bars(q.depth || {}),
        workers.length
          ? el('table', { class: 'runs' },
              el('thead', {}, el('tr', {},
                el('th', { text: 'worker' }),
                el('th', { class: 'n', text: 'holding' }),
                el('th', { text: 'lease' }))),
              el('tbody', {}, workers.map((w) => el('tr', {},
                el('td', { class: 'pkg', text: w.worker }),
                el('td', { class: 'n', text: String(w.jobs_held) }),
                el('td', {}, el('span', {
                  class: `tag ${w.lease_expires_in_seconds < 0 ? 'divergent' : 'normalized'}`,
                  text: w.lease_expires_in_seconds < 0
                    ? `lapsed ${-w.lease_expires_in_seconds}s ago`
                    : `${w.lease_expires_in_seconds}s left`,
                }))))))
          : el('p', { class: 'empty', text: 'No worker is holding a lease.' }));

  view.replaceChildren(
    el('p', {}, el('a', { href: '/', text: '← the corpus' })),
    el('div', { class: 'verdict-head' },
      el('h1', { text: 'Fleet' }),
      el('p', { class: 'purl', text: 'Whether the thing is running, and whether anything is stuck.' })),
    el('section', { class: 'panel' }, queuePanel),
    el('section', { class: 'panel' },
      el('h2', { text: 'What the corpus has reached' }),
      bars(d.corpus.by_outcome || {}),
      el('p', { class: 'note' },
        `${d.corpus.evidence} of ${d.corpus.runs} runs are evidence about a package.`)),
    el('section', { class: 'panel' },
      el('h2', { text: 'Runs we could not complete' }),
      Object.keys(d.corpus.by_fault || {}).length
        ? bars(d.corpus.by_fault)
        : el('p', { class: 'empty', text: 'None.' }),
      el('p', { class: 'note' },
        'A separate denominator. A build we could not run is not a package that failed to '
        + 'reproduce, and adding the two would answer neither question.')),
  );
}
