# Security policy

## Supported version

Security fixes are applied to the current `main` branch.

## Reporting a vulnerability

Do not publish maFiles, `shared_secret`, lookup tokens, primary IDs, aliases, production KV exports or screenshots containing live Steam Guard codes in a public issue.

Report vulnerabilities privately to the repository owner through GitHub Security Advisories when enabled.

## Intended security properties

- The raw maFile never leaves the browser.
- Only `shared_secret` and an optional account label enter the encrypted payload.
- Payload encryption uses AES-256-GCM with a random 256-bit data key and 96-bit IV.
- Access codes are processed by PBKDF2-SHA-256 and never sent to the API in plaintext.
- A separate HKDF-derived AES-GCM key wraps the random data key for each access code.
- API routes do not use cookies and enforce same-origin browser requests.
- API responses are non-cacheable.
- No third-party JavaScript is loaded.

## Out of scope / limitations

- A malicious or compromised deployment can replace client JavaScript and capture future input.
- A compromised browser, extension, operating system or clipboard can expose secrets.
- Workers KV is eventually consistent; alias changes and deletion may take time to propagate.
- The approximate KV rate limiter is not atomic and is not a substitute for Cloudflare WAF Rate Limiting or Durable Objects.
- Hosting a second factor online reduces factor separation compared with Steam's official mobile authenticator.
