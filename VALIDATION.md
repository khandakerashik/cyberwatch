# Validation — CyberWatch 2.0.1

## Newsboard relevance fix — 30 October 2026

- `npm run check` passed: shared-rule generation consistency, JavaScript syntax checks, all four JavaScript test files, 128 Python tests, and snapshot/curated-data validation.
- Six focused Chromium checks passed: an older snapshot's GM driver-tracking settlement was excluded from Newsboard, a genuine data-breach story remained visible, searching did not bypass the relevance gate, Newsletters retained broader publisher coverage, returning to Newsboard reapplied the filter, and no unhandled JavaScript errors occurred. These checks used intercepted fixtures, not synthetic records added to the bundled snapshot.
- Regression coverage includes the exact reported GM headline, consent-only tracking disputes, unrelated business news, stale matched keywords, retained and failed-source records, source budgets, metadata validation, and Python/browser policy parity across the test corpus and every bundled news record.
- Positive cases include data-breach settlements, crypto hacks, SSH backdoors, prompt injection, exposed credentials, telecom attacks, and cybersecurity education. Official advisory streams remain eligible.
- The bundled snapshot was reassessed offline: all 294 news records received a relevance decision, and 35 broader publisher updates were excluded from Newsboard. The snapshot still contains 481 total records; Newsboard admits 432 records including eligible advisories, and Newsletters retains its 294 news records.
- Original article dates and source-check timestamps were preserved. This release did not perform a new live collection. The exact GM title was not present in the bundled snapshot; its exclusion was verified with regression and browser fixtures.

## Previous live collection baseline — 2.0.0

Bundled collection checked at **30 October 2026, 22:30:25 BDT**. These are observed results for this snapshot, not guarantees of future publisher availability.

### Previous automated and browser verification

- `npm run check` passed: JavaScript syntax checks, all three JavaScript regression suites, 114 Python tests, and snapshot/curated-data validation.
- 33 desktop/mobile browser checks passed, covering navigation, composed filters, reading, saving, load more, escaping of hostile text, image captions, responsive layout and footer spacing.
- 21 live-service integration checks passed using the actual Waitress application, API, frontend and collector. A real manual refresh completed and published a validated snapshot with per-source errors recorded.
- Browser checks used Chromium at 1440 × 1000 and 375 × 900. No unhandled JavaScript errors were observed. All six mobile menu buttons fit the 375-pixel viewport; page content had no horizontal overflow.
- Legacy reviewed records remain valid. No synthetic browser-test records were written into the delivered snapshot.

### Previously collected snapshot

| Measure | Result |
| --- | ---: |
| Records | 481 |
| Automated source channels | 45 |
| Reviewed inputs | 2 |
| Successful automated source checks | 43 |
| Source checks reporting errors | 2 |
| Full-text reader items | 21 |
| Excerpt reader items | 398 |
| Items carrying publisher image metadata | 161 |

The exact BBC Binance headline supplied with the request was collected through the normal keyword-filtered RSS path, without a hardcoded record. Washington Post Technology also returned related crypto-hack reporting through its current official RSS endpoint. NGINX, Python, GitLab and Node.js channels all supplied usable records.

### Source availability at the previous live check

| Source channel | Result | Records in snapshot |
| --- | --- | ---: |
| CISA Known Exploited Vulnerabilities | ok | 20 |
| CERT-EU Security Advisories | ok | 10 |
| Google Chrome Releases | ok | 4 |
| The Hacker News | ok | 30 |
| Cybernews | ok | 30 |
| BleepingComputer | ok | 25 |
| SecurityWeek | ok | 20 |
| Help Net Security | ok | 20 |
| Palo Alto Networks · Unit 42 | ok | 13 |
| CrowdStrike | ok | 16 |
| PHP · Official updates | ok | 10 |
| Microsoft Security | ok | 14 |
| Cisco Talos | ok | 15 |
| BGD e-GOV CIRT · Advisories | ok | 2 |
| BGD e-GOV CIRT · Alerts | ok | 6 |
| BGD e-GOV CIRT · Activities | ok | 4 |
| Bangladesh Cyber Security Intelligence | ok | 9 |
| The Daily Star | ok | 1 |
| Dhaka Tribune | ok | 2 |
| The Business Standard | error | 3 |
| The Financial Express | ok | 1 |
| BBC · Technology | ok | 4 |
| BBC · World | ok | 1 |
| BBC · Business | ok | 0 |
| The Washington Post · Technology | ok | 3 |
| The Washington Post · World | ok | 0 |
| The Washington Post · Business | ok | 0 |
| The Guardian · Data and computer security | ok | 7 |
| Sky News · Technology | ok | 1 |
| Al Jazeera · World | ok | 1 |
| NPR · Technology | ok | 1 |
| Deutsche Welle · World | ok | 3 |
| France 24 · World | ok | 2 |
| ABC Australia · Technology | ok | 1 |
| The New York Times · Technology | error | 0 |
| The Record | ok | 5 |
| The Register · Security | ok | 30 |
| Dark Reading | ok | 30 |
| NGINX · Security advisories | ok | 20 |
| Python · Security advisories | ok | 30 |
| Python · Security releases | ok | 5 |
| GitLab · Security releases | ok | 30 |
| Node.js · Security advisories | ok | 7 |
| Ubuntu · Security notices | ok | 10 |
| PHP · Security releases | ok | 20 |
| Verified incident reports | snapshot | 8 |
| Bangladesh · Reviewed reports | snapshot | 7 |

The New York Times technology endpoint did not return a usable feed in this environment. The Business Standard publisher metadata collection was incomplete; previously available records were retained. These failures remain visible in Sources, and successful feeds still publish. Healthy channels with zero records had no unique eligible stories in the current feed/retention window after filtering and deduplication.

## Network and content boundaries

Live collection was verified through the explicitly configured trusted HTTP CONNECT proxy because this test environment requires that egress route. The direct connection path has offline tests for public DNS validation and address pinning, but this environment does not allow an unproxied external end-to-end check. TLS certificate checks were not disabled.

Full articles depend on source permission, robots rules, source availability and extraction quality. Partial, restricted and unavailable content is labelled. Images are public publisher/CDN URLs, not an offline image archive. Neither worldwide coverage nor access to every article is claimed.
