/* DNS Propagation Checker: asks several public DNS-over-HTTPS resolvers the same question from the browser
   and compares the answers. No dependencies, no inline code (CSP: script-src 'self'). */
(function () {
  'use strict';

  // Only resolvers that were tested from a real browser page and allow cross-origin JSON requests.
  // Hosts here must match connect-src in index.html exactly.
  var RESOLVERS = [
    { id: 'google', name: 'Google Public DNS', host: 'dns.google', url: 'https://dns.google/resolve' },
    { id: 'cloudflare', name: 'Cloudflare 1.1.1.1', host: 'cloudflare-dns.com', url: 'https://cloudflare-dns.com/dns-query' },
    { id: 'dnssb', name: 'DNS.SB', host: 'dns.sb', url: 'https://dns.sb/dns-query' },
    { id: 'alidns', name: 'AliDNS (Alibaba)', host: 'dns.alidns.com', url: 'https://dns.alidns.com/resolve' }
  ];
  var TYPES = { A: 1, AAAA: 28, CNAME: 5, MX: 15, NS: 2, TXT: 16, SOA: 6, CAA: 257 };
  var STATUS = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
  var TIMEOUT_MS = 8000;
  var AUTO_SECONDS = 30;

  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  // ---- Input handling ----
  function normalizeDomain(input) {
    return String(input || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '').replace(/\.+$/, '');
  }
  function validDomain(d) {
    if (!d || d.length > 253) return false;
    return d.split('.').every(function (l) { return /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(l) || /^xn--[a-z0-9-]+$/i.test(l); });
  }

  // ---- Querying ----
  async function queryResolver(r, domain, type) {
    var out = { resolver: r, ok: false, error: null, ms: null, status: null, answers: [], ttl: null, ad: false };
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, TIMEOUT_MS);
    var t0 = performance.now();
    try {
      var res = await fetch(r.url + '?name=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type), {
        headers: { accept: 'application/dns-json' }, signal: ctl.signal, credentials: 'omit', cache: 'no-store'
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var data = await res.json();
      out.ms = Math.round(performance.now() - t0);
      out.status = typeof data.Status === 'number' ? data.Status : null;
      if (out.status === null) throw new Error('not a DNS JSON answer');
      out.ad = data.AD === true;
      var want = TYPES[type];
      var rows = Array.isArray(data.Answer) ? data.Answer : [];
      // Keep records of the requested type, plus the CNAME chain that led to them.
      out.answers = rows.filter(function (x) { return x && (x.type === want || x.type === 5) && typeof x.data === 'string'; })
        .map(function (x) { return { type: x.type, data: x.data, ttl: typeof x.TTL === 'number' ? x.TTL : null }; });
      var ttls = out.answers.map(function (x) { return x.ttl; }).filter(function (t) { return t !== null; });
      out.ttl = ttls.length ? Math.min.apply(null, ttls) : null;
      out.ok = true;
    } catch (e) {
      out.ms = Math.round(performance.now() - t0);
      out.error = e && e.name === 'AbortError' ? 'timeout after ' + (TIMEOUT_MS / 1000) + ' s' : (e && e.message) || 'request failed';
    } finally { clearTimeout(timer); }
    return out;
  }

  // Canonical text for one record, used for comparison and display.
  function canon(a) {
    var s = String(a.data).trim();
    if (a.type === 16) return s.replace(/"\s+"/g, '').replace(/^"|"$/g, '');
    if (a.type === 257) return s.replace(/\s+/g, ' ');
    return s.replace(/\s+/g, ' ').toLowerCase().split(' ').map(function (t) { return t.replace(/\.$/, ''); }).join(' ');
  }
  function answerSet(o, type) {
    return o.answers.map(function (a) { return (a.type === 5 && type !== 'CNAME' ? 'CNAME ' : '') + canon(a); }).sort();
  }
  function groupKey(o, type) {
    return (STATUS[o.status] || 'RCODE' + o.status) + '|' + answerSet(o, type).join('\n');
  }

  // ---- Comparison ----
  function compare(results, type, expect) {
    var ok = results.filter(function (o) { return o.ok; });
    var groups = {};
    ok.forEach(function (o) { var k = groupKey(o, type); o.key = k; (groups[k] = groups[k] || []).push(o); });
    var keys = Object.keys(groups).sort(function (a, b) { return groups[b].length - groups[a].length; });
    var majority = keys.length ? keys[0] : null;
    var tie = keys.length > 1 && groups[keys[0]].length === groups[keys[1]].length;
    ok.forEach(function (o) {
      o.differs = keys.length > 1 && o.key !== majority;
      var ms = o.key.split('|')[0];
      o.statusDiffers = keys.length > 1 && ms !== majority.split('|')[0];
      o.answersDiffers = keys.length > 1 && o.key.slice(ms.length) !== majority.slice(majority.split('|')[0].length);
    });
    if (expect) {
      var e = normExpect(expect, type);
      ok.forEach(function (o) {
        o.match = answerSet(o, type).some(function (s) { return matchExpect(s, e, type); });
      });
    }
    return { ok: ok.length, total: results.length, groups: keys.length, tie: tie, consistent: ok.length > 0 && keys.length === 1 };
  }
  function normExpect(v, type) {
    var s = String(v).trim().replace(/\s+/g, ' ');
    if (type === 'TXT') return s.replace(/^"|"$/g, '');
    if (type === 'CAA') return s;
    return s.toLowerCase().split(' ').map(function (t) { return t.replace(/\.$/, ''); }).join(' ');
  }
  function matchExpect(rec, exp, type) {
    if (type === 'TXT') return rec === exp || rec.indexOf(exp) !== -1;
    var r = rec.replace(/^cname /, '');
    return r === exp;
  }

  // ---- Rendering ----
  var views = { placeholder: $('placeholderState'), results: $('recordsContainer'), error: $('errorContainer') };
  function setView(name) { Object.keys(views).forEach(function (k) { views[k].hidden = k !== name; }); }
  function renderError(msg) {
    var box = views.error;
    box.replaceChildren();
    var s = el('div', 'state fail error-message');
    s.setAttribute('role', 'alert');
    s.append(el('h2', 'state-title', 'Cannot check'));
    s.append(el('p', null, msg));
    box.append(s);
  }

  function cell(tag, cls, text) { return el(tag, cls || null, text); }

  function render(domain, type, expect, results, cmp, when) {
    var box = views.results;
    box.replaceChildren();

    var verdictClass, title, detail;
    if (!cmp.ok) {
      verdictClass = 'fail'; title = 'No resolver answered';
      detail = 'Every request failed or was blocked, see the table. Check your connection, content blockers or DNS filtering.';
    } else if (cmp.consistent) {
      verdictClass = 'ok'; title = 'Consistent';
      detail = cmp.ok + ' of ' + cmp.total + ' resolvers return the same answer for ' + domain + ' ' + type + '.';
      if (cmp.ok < cmp.total) detail += ' The others did not respond and are not counted.';
    } else {
      verdictClass = 'warn'; title = 'Differing answers: likely still propagating or geo/anycast-dependent';
      detail = cmp.groups + ' different answers across ' + cmp.ok + ' resolvers' + (cmp.tie ? ' (no clear majority)' : '') + '. Highlighted cells differ from the majority.';
      if (type === 'A' || type === 'AAAA') detail += ' Round-robin and geo-DNS can also make A/AAAA sets differ legitimately.';
    }
    var s = el('div', 'state ' + verdictClass);
    s.append(el('h2', 'state-title verdict', title));
    s.append(el('p', null, detail));
    if (expect && cmp.ok) {
      var hit = results.filter(function (o) { return o.ok && o.match; }).length;
      var p = el('p', null);
      var st = el('strong', null, hit + ' of ' + cmp.ok + ' resolvers return the expected value');
      p.append(st, ' (' + expect + ').');
      s.append(p);
    }
    box.append(s);

    var scroll = el('div', 'table-scroll');
    scroll.tabIndex = 0;
    scroll.setAttribute('role', 'region');
    scroll.setAttribute('aria-label', 'Answers per resolver (scrolls sideways on narrow screens)');
    var table = el('table', 'prop-table');
    table.append(el('caption', 'sr-only', domain + ' ' + type + ' as seen by each resolver'));
    var thead = el('thead'), hr = el('tr');
    ['Resolver', 'Status', 'Answer records', 'TTL', 'Time'].concat(expect ? ['Expected'] : []).forEach(function (h) {
      var th = el('th', null, h); th.scope = 'col'; hr.append(th);
    });
    thead.append(hr); table.append(thead);

    var tbody = el('tbody');
    results.forEach(function (o) {
      var tr = el('tr');
      var th = el('th', 'res-name'); th.scope = 'row';
      th.append(el('span', null, o.resolver.name), el('small', null, o.resolver.host));
      tr.append(th);
      if (!o.ok) {
        var td = el('td', 'unreachable', 'No answer: ' + o.error);
        td.colSpan = expect ? 5 : 4;
        tr.append(td);
      } else {
        var st = cell('td', 'status' + (o.statusDiffers ? ' diff' : ''), (o.statusDiffers ? '≠ ' : '') + (STATUS[o.status] || 'RCODE ' + o.status));
        tr.append(st);
        var an = el('td', 'answers' + (o.answersDiffers ? ' diff' : ''));
        if (o.answersDiffers) an.append(el('span', 'neq', '≠ differs from majority'));
        if (!o.answers.length) an.append(el('span', 'none', 'no records'));
        o.answers.slice().sort(function (a, b) { return canonCmp(a, b, type); }).forEach(function (a) {
          an.append(el('div', 'rec', (a.type === 5 && type !== 'CNAME' ? 'CNAME ' : '') + (a.type === 16 ? canon(a) : a.data)));
        });
        tr.append(an);
        tr.append(cell('td', 'num', o.ttl === null ? '–' : o.ttl + ' s'));
        tr.append(cell('td', 'num', o.ms + ' ms'));
        if (expect) tr.append(cell('td', 'exp ' + (o.match ? 'yes' : 'no'), o.match ? 'match' : 'no match'));
      }
      tbody.append(tr);
    });
    table.append(tbody);
    scroll.append(table);
    box.append(scroll);

    box.append(el('p', 'count', 'Checked ' + when.toLocaleTimeString() + '. TTL is the lowest remaining TTL in the answer, it differs between resolvers by cache age and is not compared.'));

    var warn = el('div', 'caveat');
    warn.append(el('strong', null, 'A coarse view, not a global one. '));
    warn.append('These resolvers are anycast services that share caches across many locations, and a browser cannot choose which node answers or query authoritative servers directly. ' +
      'Agreement here does not prove the change has reached every resolver worldwide, and a difference may also be geo-DNS or load balancing rather than propagation. ' +
      'Only resolvers that allow cross-origin requests from a web page are used (' + RESOLVERS.length + ' here).');
    box.append(warn);

    box.append(siblingLinks(domain));
  }
  function canonCmp(a, b, type) {
    var x = canon(a), y = canon(b);
    if (type === 'MX') { var px = parseInt(x, 10), py = parseInt(y, 10); if (px !== py) return px - py; }
    return x < y ? -1 : x > y ? 1 : 0;
  }

  function siblingLinks(domain) {
    var wrap = el('p', 'provider');
    wrap.append('Also check ' + domain + ': ');
    [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC'], ['bimi', 'BIMI'], ['dnssec', 'DNSSEC'], ['caa', 'CAA'], ['mx', 'MX'], ['ssl', 'SSL'], ['rdap', 'RDAP'], ['ip', 'IP']].forEach(function (t, i) {
      if (i) wrap.append(' · ');
      var a = el('a', 'link', t[1]);
      a.href = 'https://' + t[0] + '.hbenali.ovh/?domain=' + encodeURIComponent(domain);
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      wrap.append(a);
    });
    return wrap;
  }

  // ---- Flow ----
  var domainInput = $('domainInput'), typeSelect = $('typeSelect'), expectInput = $('expectInput');
  var checkBtn = $('checkBtn'), btnText = $('btnText'), btnLoader = $('btnLoader');
  var autoBox = $('autoRefresh'), autoNote = $('autoNote');
  var busy = false, countdown = 0, ticker = null;

  Object.keys(TYPES).forEach(function (t) { var o = el('option', null, t); o.value = t; typeSelect.append(o); });
  typeSelect.value = 'A';

  function setLoading(on) {
    busy = on;
    checkBtn.disabled = on;
    btnText.textContent = on ? 'Checking' : 'Check propagation';
    btnLoader.hidden = !on;
    btnLoader.className = on ? 'loader' : '';
  }

  async function run() {
    if (busy) return;
    var domain = normalizeDomain(domainInput.value);
    var type = typeSelect.value;
    var expect = expectInput.value.trim();
    if (!domain) { setView('error'); renderError('Please enter a domain name.'); return; }
    if (!validDomain(domain)) { setView('error'); renderError('That is not a valid domain name.'); return; }
    if (!Object.prototype.hasOwnProperty.call(TYPES, type)) { setView('error'); renderError('Unsupported record type.'); return; }
    if (expect.length > 500) { setView('error'); renderError('The expected value is too long (500 characters max).'); return; }
    domainInput.value = domain;
    try {
      var q = new URLSearchParams({ domain: domain, type: type });
      if (expect) q.set('expect', expect);
      history.replaceState(null, '', '?' + q.toString());
    } catch (e) { /* history may be unavailable; not essential */ }
    setLoading(true);
    try {
      var results = await Promise.all(RESOLVERS.map(function (r) { return queryResolver(r, domain, type); }));
      var cmp = compare(results, type, expect);
      render(domain, type, expect, results, cmp, new Date());
      setView('results');
    } catch (err) {
      setView('error'); renderError((err && err.message) || 'Unknown error');
    } finally {
      setLoading(false);
      resetCountdown();
    }
  }

  function resetCountdown() {
    countdown = AUTO_SECONDS;
    updateAutoNote();
  }
  function updateAutoNote() {
    autoNote.textContent = autoBox.checked ? 'Next check in ' + countdown + ' s' : '';
  }
  function tick() {
    if (!autoBox.checked || busy) return;
    countdown -= 1;
    if (countdown <= 0) { run(); return; }
    updateAutoNote();
  }
  autoBox.addEventListener('change', function () {
    if (autoBox.checked) {
      resetCountdown();
      if (!ticker) ticker = setInterval(tick, 1000);
    } else {
      if (ticker) { clearInterval(ticker); ticker = null; }
      updateAutoNote();
    }
  });

  $('lookupForm').addEventListener('submit', function (e) { e.preventDefault(); run(); });

  setView('placeholder');

  var qs = new URLSearchParams(window.location.search);
  var pd = qs.get('domain'), pt = (qs.get('type') || '').toUpperCase(), pe = qs.get('expect');
  if (pt && Object.prototype.hasOwnProperty.call(TYPES, pt)) typeSelect.value = pt;
  if (pe) expectInput.value = pe.slice(0, 500);
  if (pd) { domainInput.value = pd; run(); }

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
})();
