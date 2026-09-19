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
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  const r = await fetch(path, {
    method: opts.method || 'GET',
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
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
];

async function route() {
  readFragment();
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
  entry: 'Something about the archive entry differs, rather than the file it holds.',
};

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
function ledgerPanel(d) {
  if (!d.applied.length) {
    return panel('The stabilizers', el('p', { class: 'note' },
      'No pass changed anything on either side, so the two artifacts were compared exactly as published. The verdict owes nothing to normalization.'));
  }
  const max = Math.max(...d.applied.map((p) => p.entries), 1);
  const rows = d.applied.map((p) => el('tr', {},
    el('td', {},
      el('code', { text: p.id }),
      p.caps ? el('span', { class: 'tag normalized_with_caveats', text: 'caps' }) : null),
    el('td', { class: 'n', text: p.entries }),
    el('td', { class: 'bar-cell' },
      el('div', { class: 'bar-track' },
        el('div', { class: 'bar-fill', style: [['width', `${(p.entries / max) * 100}%`], ['background', RISK_COLOUR[p.risk] || 'var(--dim)']] }))),
    el('td', { class: 'dim', text: p.risk }),
    el('td', {}, p.provenance === 'builtin'
      ? el('span', { class: 'dim', text: 'builtin' })
      : el('span', { class: 'diff', text: p.who })),
    el('td', { class: 'n dim', text: p.bytes ? bytes(p.bytes) : '—' })));

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

// Every member, most interesting first. A hundred identical members must not bury the ten that
// differ, and a list capped at five hundred that sorted by path would cap away exactly the rows
// somebody came to read.
function membersPanel(d, runId) {
  const rows = d.members.flatMap((m) => {
    const [label, colour, why] = MEMBER_STATE[m.status] || [m.status, 'var(--dim)', ''];
    // Only a member with something to look at is openable: two identical copies have no diff and
    // offering one would be offering an empty panel.
    const worth = m.status !== 'identical';
    const slot = el('td', { colspan: 6, class: 'member-slot' });
    const open = () => {
      // The open member goes in the fragment, so "look at this file" is a link somebody can send.
      // A fragment rather than the path, because the page is still the run's: a reader who clears
      // it is back where they were rather than somewhere new.
      const f = new URLSearchParams({ member: m.path });
      history.replaceState({}, '', `${location.pathname}#${f}`);
      openMember(runId, m.path, slot, {});
    };
    // Entered on a link to this member, so open it without waiting to be clicked.
    if (worth && OPEN_ON_LOAD && OPEN_ON_LOAD.member === m.path) {
      const want = OPEN_ON_LOAD;
      queueMicrotask(() => openMember(runId, m.path, slot, { view: want.view }));
    }
    return [el('tr', { class: worth ? 'openable' : '' },
      el('td', { class: 'url' }, worth
        ? el('button', { class: 'member-link', onclick: open, title: 'open this member', text: m.path })
        : el('code', { text: m.path })),
      el('td', {}, el('span', { class: 'member-state', title: why },
        el('i', { style: [['background', colour]] }), label)),
      // What differed about it before any pass ran. The row that matters is an *identical* member
      // with `entry:mode` here: the file is byte for byte what was published, its archive entry was
      // not, and a pass removed the difference — so the divergence was about how it was packed
      // rather than about what anybody wrote.
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

// `#member=<path>&view=hex` on a run page. Read once at navigation rather than watched, so a
// reader who opens a second member does not find the first one reopening under them.
let OPEN_ON_LOAD = null;
function readFragment() {
  try {
    const f = new URLSearchParams(location.hash.replace(/^#/, ''));
    const member = f.get('member');
    OPEN_ON_LOAD = member ? { member, view: f.get('view') || undefined } : null;
  } catch {
    OPEN_ON_LOAD = null;
  }
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

  const reload = (next) => openMember(runId, path, slot, { ...state, ...next, offset: next.offset });
  const wantHex = state.view ? state.view === 'hex' : d.binary;
  const raw = (side) => `/v1/runs/${encodeURIComponent(runId)}/member/raw?` +
    new URLSearchParams({ path, side });

  const tab = (label, key, enabled) => el('button', {
    class: 'chip',
    'aria-pressed': (key === 'hex') === wantHex,
    disabled: !enabled,
    onclick: () => {
      const f = new URLSearchParams({ member: path, view: key });
      history.replaceState({}, '', `${location.pathname}#${f}`);
      openMember(runId, path, slot, { ...state, view: key });
    },
    text: label,
  });

  slot.replaceChildren(el('div', { class: 'member-open' },
    el('div', { class: 'filters' },
      tab('text', 'text', !!d.text),
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

    !d.in_upstream || !d.in_rebuild
      ? el('p', { class: 'withheld-note' },
          el('strong', { text: d.in_upstream ? 'Only the published artifact has this. ' : 'Only the rebuild has this. ' }),
          d.in_upstream
            ? 'The build did not produce it, so there is nothing to compare against — what is below is the published file itself.'
            : 'The published artifact does not contain it, so the build produced something that was never shipped. What is below is that file.')
      : null,

    d.binary && !state.view
      ? el('p', { class: 'note empty' },
          `Opened as hex: ${d.binary_because}. The text view is off for this member because rendering these bytes as lines would invent structure they do not have.`)
      : null,

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
    fillLater(
      comparison,
      api(`/v1/runs/${encodeURIComponent(id)}/diff`).catch(() => null),
      (d) => [
        ladderPanel(d),
        censusPanel(d),
        contentsPanel(d),
        ledgerPanel(d),
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

    record.assumptions?.length ? panel('What this had to assume', el('div', {},
      el('ul', { class: 'assumptions' }, record.assumptions.map((a) => el('li', { text: a }))),
      el('p', { class: 'note empty' },
        'A verdict reached under assumptions is a different claim from one reached under none, which is why they are listed beside it rather than folded into it.'))) : null,

    record.guard_trips?.length ? panel('Why this is void', el('div', {},
      el('ul', { class: 'assumptions' }, record.guard_trips.map((g) => el('li', { text: g }))),
      el('p', { class: 'note empty' },
        'The artifact under test reached the build over the network. Whatever came out may be perfectly honest and we cannot tell, which is exactly what void means.'))) : null,

    panel('What it cost', costs(record)),

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
