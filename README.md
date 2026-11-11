# DNS Propagation Checker

A free, single-page DNS propagation checker. Live at [propagation.hbenali.ovh](https://propagation.hbenali.ovh).

No backend, no build step, no dependencies: static HTML, CSS and one small script calling public DNS-over-HTTPS JSON APIs from the browser.

## Features

- **Same question, several resolvers**: one domain and record type (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA) sent to Google, Cloudflare, DNS.SB and AliDNS
- **Comparison table**: status, answer records, lowest TTL and response time per resolver, with cells that differ from the majority highlighted
- **Verdict**: "consistent", or "differing answers: likely still propagating or geo/anycast-dependent"
- **Expected value** (optional): shows which resolvers already return it
- **Re-check** button and an optional auto-refresh every 30 s
- **Cross-links** to the sibling tools for the same domain
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP (`script-src 'self'`)

## Limits

Resolvers are anycast services with shared caches, and a browser cannot pick the node that answers or query authoritative servers directly. This is a coarse view, not a global one. Only resolvers that send CORS headers and return JSON can be used from a web page. Tested from a browser page: Google, Cloudflare, DNS.SB and AliDNS work; Quad9, AdGuard, OpenDNS, NextDNS and Mullvad do not (no CORS headers, no JSON endpoint, or an HTTP 400 for JSON-style queries).

## URL parameters

`?domain=example.com&type=MX&expect=mail.example.com` runs a check on load. `type` defaults to `A`, `expect` is optional.

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
