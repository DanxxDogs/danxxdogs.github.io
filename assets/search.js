/* Danxx Dogs scam DB search: client-side, reads the cards already on the page. */
(function (root) {
  var MISS = "Not in our database yet \u2014 that does NOT mean it's safe. Run /sniff 0x\u2026 in the Dip Club (@DanxxDogsSniffBot). NFA/DYOR.";
  function norm(s) { return String(s || '').replace(/\s+/g, '').toLowerCase(); }
  function search(entries, raw) {
    var q = norm(raw).replace(/^\$+/, '');
    if (q.length < 2) return { kind: 'short', results: [] };
    var isHex = /^0x[0-9a-f]+$/.test(q);
    var out = [];
    entries.forEach(function (e) {
      var addrs = e.addrs.map(norm), m = null;
      if (isHex) {
        addrs.forEach(function (a) {
          var hexes = a.match(/0x[0-9a-f]+/g) || [];
          hexes.forEach(function (h) {
            if (h === q && q.length === 42) m = 'exact';
            else if (!m && ((q.length >= 6 && h.indexOf(q) > -1) || (q.length === 42 && h.length >= 8 && q.indexOf(h) === 0))) m = 'partial';
          });
        });
      } else {
        var t = norm(e.ticker), n = norm(e.title);
        if (t && t === q) m = 'ticker';
        else if (q.length >= 3 && n.indexOf(q) > -1) m = 'name';
      }
      if (m) out.push({ entry: e, match: m });
    });
    var rank = { exact: 0, ticker: 1, partial: 2, name: 3 };
    out.sort(function (a, b) { return rank[a.match] - rank[b.match]; });
    return { kind: out.length ? 'hit' : 'miss', results: out };
  }
  function fromDom(doc) {
    return Array.prototype.map.call(doc.querySelectorAll('#db article.db'), function (a) {
      var id = (a.querySelector('.id') || {}).textContent || '';
      if (!a.id) a.id = id.toLowerCase();
      var h3 = a.querySelector('h3'), title = h3 ? h3.textContent : '';
      var tk = title.match(/\(([A-Za-z0-9]{2,15})\)/);
      var links = [];
      a.querySelectorAll('a[href^="http"]').forEach(function (l) { links.push({ href: l.href, text: l.textContent }); });
      a.querySelectorAll('li').forEach(function (li) { (li.textContent.match(/https?:\/\/\S+/g) || []).forEach(function (u) { links.push({ href: u, text: 'Receipt \u2197' }); }); });
      return {
        id: id, anchor: a.id, title: title, ticker: tk ? tk[1] : '',
        tags: Array.prototype.map.call(a.querySelectorAll('.tag'), function (t) { return t.textContent; }),
        addrs: Array.prototype.map.call(a.querySelectorAll('.addr code'), function (c) { return c.textContent; }),
        facts: Array.prototype.slice.call(a.querySelectorAll('h4 + ul li'), 0, 2).map(function (l) { return l.textContent; }),
        links: links
      };
    });
  }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function render(res, box) {
    if (res.kind === 'short') { box.innerHTML = ''; return; }
    if (res.kind === 'miss') { box.innerHTML = '<p class="sr-miss">' + esc(MISS) + '</p>'; return; }
    var note = res.results.some(function (r) { return r.match !== 'exact'; })
      ? '<p class="sr-note">\u26a0\ufe0f Partial / ticker / name match. Copycats share tickers and names, so match the FULL contract address before you trust anything. NFA/DYOR.</p>' : '';
    box.innerHTML = '<p class="muted">' + res.results.length + ' match' + (res.results.length > 1 ? 'es' : '') + ' in our scam DB:</p>' + note +
      res.results.map(function (r) {
        var e = r.entry;
        return '<div class="sr-item"><a class="id" href="#' + esc(e.anchor) + '">' + esc(e.id) + '</a> ' +
          e.tags.map(function (t) { return '<span class="tag">' + esc(t) + '</span>'; }).join(' ') +
          '<h3><a href="#' + esc(e.anchor) + '">' + esc(e.title) + '</a></h3>' +
          (r.match === 'exact' ? '<p class="sr-exact">Full contract address match.</p>' : '') +
          '<ul>' + e.facts.map(function (f) { return '<li>' + esc(f) + '</li>'; }).join('') + '</ul><p>' +
          e.links.map(function (l) { return '<a href="' + esc(l.href) + '" target="_blank" rel="noopener">' + esc(l.text) + '</a>'; }).join(' \u00b7 ') +
          (e.links.length ? ' \u00b7 ' : '') + '<a href="#' + esc(e.anchor) + '">Full entry \u2193</a></p></div>';
      }).join('');
  }
  root.DDSearch = { search: search, MISS: MISS };
  if (typeof document !== 'undefined') document.addEventListener('DOMContentLoaded', function () {
    var entries = fromDom(document);
    if (location.hash) { var t = document.getElementById(location.hash.slice(1)); if (t) t.scrollIntoView(); }
    document.querySelectorAll('form.ddsearch').forEach(function (f) {
      var inp = f.querySelector('input'), box = f.parentNode.querySelector('.sr-results');
      var run = function () { render(search(entries, inp.value), box); };
      f.addEventListener('submit', function (ev) { ev.preventDefault(); run(); });
      inp.addEventListener('input', run);
      var p = new URLSearchParams(location.search).get('q'); if (p) { inp.value = p; run(); }
    });
  });
})(typeof window !== 'undefined' ? window : module.exports);
