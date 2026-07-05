# Security Policy

ShieldFive takes the security of `@shieldfive/crypto` seriously. This
document describes how to report a vulnerability, what we commit to, and
the safe-harbor terms for security researchers.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.** Instead, email
us directly:

- **Email:** `security@shieldfive.com`
- **PGP key:** Not yet published. Encrypt with a temporary key on
  request, or send in plaintext — we'd rather know about the issue
  than have it sit in your inbox. The permanent PGP key fingerprint
  will be published at v1.0.0 stable release alongside the URL
  `https://shieldfive.com/.well-known/security/pgp-key.txt`.

If you cannot encrypt the report, send it in plaintext anyway — we would
rather hear about a vulnerability in plaintext than not at all. We will
follow up over an encrypted channel.

### What to include

1. A description of the vulnerability and its impact.
2. Steps to reproduce, including a minimal proof-of-concept if possible.
3. The library version and runtime environment (Node version, browser,
   bundler).
4. Whether the issue is already public or has been disclosed elsewhere.
5. Your name and a way to contact you (or "anonymous" if you prefer).

## Our commitments

These windows match the public program at
<https://shieldfive.com/security/bug-bounty>, which is the canonical
source; if the two ever differ, the public program governs. They reflect
the realistic capacity of a small team, not aspiration; we will explain
any slippage in writing.

| Step                  | Commitment      |
| --------------------- | --------------- |
| Acknowledge receipt   | within 72 hours |
| Initial triage reply  | within 7 days   |
| Critical patch target | 14 days         |
| High patch target     | 30 days         |
| Medium patch target   | 90 days         |
| Low / informational   | best effort     |

Severity is assigned by the impact described in
[`spec/threat-model.md`](spec/threat-model.md): Critical = plaintext or
key recovery, or RCE; High = integrity bypass that returns mutated
plaintext as if authentic; Medium = exploitable implementation error or
spec-vs-implementation drift with security implications; Low =
defense-in-depth. We explain our severity assignment in every reply.

We will:

- Acknowledge your report within the windows above.
- Keep you informed of our investigation.
- Credit you in the release notes (with your permission, or anonymously).
- Coordinate public disclosure with you. We default to a 90-day disclosure
  window, but will move faster if there is active exploitation in the
  wild and slower if a coordinated multi-party fix is in progress.
- Publish a CVE when appropriate.

We will *not*:

- Take legal action against researchers acting in good faith (see
  Safe Harbor below).
- Demand silence as a condition of bounty or credit.

## Safe Harbor

Security research conducted in accordance with this policy is authorized.
Specifically, we will not pursue civil claims or refer law enforcement
investigations against researchers who:

1. Make a good-faith effort to avoid privacy violations, destruction of
   data, and interruption or degradation of our services.
2. Do not access, modify, or exfiltrate data belonging to anyone other
   than themselves or research accounts.
3. Report the vulnerability promptly through this policy's channels.
4. Do not exploit the vulnerability beyond what is necessary to confirm
   it.
5. Do not publicly disclose the vulnerability before we have had a
   reasonable opportunity to remediate it (the timelines above).

Activities consistent with this policy are considered authorized conduct,
and we will not initiate legal action against you. If a third party
initiates legal action against you for activities conducted under this
policy, we will make this authorization clear.

## Bug bounty

ShieldFive operates a paid bug bounty program covering this
open-source crypto library. Reward tiers:

- Critical: up to €1000
- High: up to €500
- Medium: up to €250

Lower-impact findings receive public credit (CVE, release notes,
dedicated thank-you page) and product credits.

For current scope, rules of engagement, submission instructions,
and the safe-harbor statement, see
https://shieldfive.com/security/bug-bounty.

## Out of scope

The following are *not* in scope for this library's security policy and
should be reported elsewhere or not at all:

- Vulnerabilities in dependencies (`@noble/post-quantum`,
  `libsodium-wrappers-sumo`) — report those upstream.
- Vulnerabilities in the host application running this library — those
  are the application's responsibility.
- Side-channel attacks against the underlying crypto runtime
  (browser SubtleCrypto, libsodium) — those are out of scope per the
  threat model in `spec/threat-model.md`.
- Theoretical attacks on the underlying primitives (AES, ChaCha20,
  ML-KEM-1024) — these belong in the academic literature.
- Vulnerabilities that require an attacker to already control the user's
  device.

## Cryptographic specifications

Implementation choices and threat model are documented in:

- [`spec/format-v1.md`](spec/format-v1.md) — wire format specification
- [`spec/format-v0.md`](spec/format-v0.md) — legacy format (read-only)
- [`spec/threat-model.md`](spec/threat-model.md) — adversary model and
  comparisons

If your report concerns a property claimed in those documents not actually
holding, please cite the specific paragraph.

## Acknowledgements

With thanks to the researchers who have reported findings in good faith
(listed with their consent):

- **0xEr3n** ([x.com/0xEr3n](https://x.com/0xEr3n)) — reader-validation
  consistency hardening in the Suite 0x03 combined-key stream decrypt
  path (Low / defense-in-depth; fixed in 1.0.0-beta.3).

---

Last updated: 2026-07-05
