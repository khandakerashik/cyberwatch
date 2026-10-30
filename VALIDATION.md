# Validation — CyberWatch 3.1.0

## Current release verification

The integrated live collection completed at **31 October 2026, 00:48:10 BDT** in **10.7 seconds** in this environment. These results describe the bundled snapshot and checks performed here; they are not a guarantee of future publisher availability.

- `npm run check` passed: shared relevance-policy consistency, JavaScript syntax checks, all **six JavaScript regression files**, **172 Python tests**, and current snapshot/curated-data validation.
- **63 integrated Chromium checks** passed at a GitHub Pages-style `/cyberwatch/` subpath. They cover source metrics/filter combinations/details/source routing/CSV, documented milestone versus publication dates, leap-year calendar, keyboard month boundaries, day/month export, reader focus return, the TeamViewer excerpt and continuation notice, a licensed body over 8,000 characters, zero-word/headline-only content, all nine navigation entries, old 3.0 snapshot compatibility, and responsive behavior.
- **76 visual/integration checks** passed for Source quality, Incident history, Techniques and the reader at **1440, 900, 375 and 320 pixels**. Screenshots were visually inspected. Active mobile navigation is visible and the document has no horizontal overflow.
- **26 focused learning checks** passed: four tabs, composed technique filters, reviewed-state persistence, expanded method state, keyboard navigation/search, existing checklist/notes persistence and correct CSV state.
- **11 actual Waitress service checks** passed. The API preserves source history and 206 research records; all new JavaScript modules and publisher-content notices are served correctly; the frontend discovers the live API and renders the new pages. This smoke check did not trigger another publisher refresh.
- The new source-coverage bars were verified under the actual production Content Security Policy. No blocked inline style or JavaScript errors occurred in the final integrated browser pass.
- Regression coverage includes collection-history idempotence, missing runs, manual sources, mixed timestamp precision, invalid future history, Bangladesh date boundaries, irrelevant-news exclusion, CSV formula neutralization, relative RSS links, allowed full text, partial text, empty content, cache retention, updated publications and permission changes.
- Browser fixtures, personal progress/notes, screenshots, caches, local dependencies and runtime state are excluded from the deliverable.

### Current bundled snapshot

| Measure | Result |
| --- | ---: |
| Total retained records | 699 |
| Source registry entries | 75 |
| Automated collection channels | 73 |
| Successful latest checks | 72 |
| Failed latest checks | 1 |
| Curated channels | 2 |
| Research publication records | 206 |
| Research feed channels | 22 |
| Official edition-page monitors | 6 |
| Standards/release watch cards | 12 |
| Techniques library cards | 24 |
| Learning paths / checklist steps | 6 / 24 |
| Full source-text reader items | 52 |
| Items with publisher image metadata | 312 |
| Recorded collection-history observations | 138 |

All 28 research/standards channels passed. The crAPI feed correctly reports a healthy zero because no entries meet its retained window. The New York Times Technology feed remained unavailable; its failure is visible. The Business Standard, which failed at the previous check, recovered. Source quality therefore shows 135 successful checks out of 138 recorded observations; it does not infer uptime during unrecorded intervals or grade publisher credibility.

### Article completeness

The TeamViewer example from The Hacker News was verified against the public RSS feed. Its supplied description has 394 characters, ends mid-sentence and contains no full `content:encoded` body. The reader now preserves the supplied paragraphs, adds an explicit ellipsis, labels the record partial and provides visible continuation links. The current source policy does not claim permission to republish the entire publisher article.

Permitted text no longer falls back unnecessarily to a 120-word recap. Full release-note content from four officially licensed OWASP feeds is retained with attribution. Full source text is not a claim that an entire standards book is embedded. Complete same-version cached text survives temporary fetch failures, while changed publications, revoked policies and access restrictions cannot reuse an inappropriate old copy.

### History and persistence limits

Reported milestones come from reviewed timelines; source publication dates and catalog-addition dates remain separate. Date-only source values preserve their calendar date. Timestamped dates use Asia/Dhaka. Automated publications follow existing retention budgets; the calendar is not an exhaustive durable archive of every global incident.

Collection history retains up to 48 actual checks per source, starting with a legacy recorded attempt when available. Browser reloads do not add samples. The snapshot and existing Actions cache carry this bounded history. Long-term archival storage, incident clustering, multilingual coverage evaluation and licensed news integrations remain roadmap work.

## Previous portal baseline — 3.0.0

## Portal and Research Lab verification

The integrated collection completed at **30 October 2026, 23:59:51 BDT** in **12.4 seconds** in this environment. A subsequent offline classification refinement preserved publication dates, source check times and watch observations; it excluded one corporate policy announcement and identified three explicit guides.

- `npm run check` passed: generated-policy consistency, JavaScript syntax checks, all five JavaScript regression files, **145 Python tests**, and current snapshot/curated-data validation.
- **48 integrated Chromium checks** passed at a GitHub Pages-style `/cyberwatch/` subpath. They covered standards cards, source following and persistence, composed filters, reviewed/saved lists, export state, CSV download, article reading and focus return, learning progress, escaped personal notes, keyboard tabs/search, source-to-watch routing, old views, old snapshot compatibility and blocked browser storage.
- **Six actual Waitress service checks** passed: research metadata and all project watches reached the API, new static modules had correct content types, the frontend discovered the live service, Research Lab rendered the API snapshot, and no JavaScript page errors occurred. This smoke check did not trigger a second publisher collection.
- All three Research Lab sections were visually inspected at **1440, 900, 375 and 320 pixels**. The final functional run rechecked 1440, 900 and 375 pixels. There was no horizontal document overflow; all seven mobile navigation items fit. The narrow-screen source selector was corrected before the final pass.
- Meaningful regression cases include draft/prerelease labels, source-update timestamps, first-observation baselines, changed markers, outage retention, safe references, highest observed version selection, explicit guide classification, corporate-announcement filtering, research separation from news, and observation/publication-date boundaries.
- No browser fixtures, local study notes, screenshots or runtime state are included in the delivered snapshot.

### Bundled snapshot in 3.0.0

| Measure | Result |
| --- | ---: |
| Total records | 630 |
| Source registry entries | 67 |
| Automated collection channels | 65 |
| Successful automated checks | 63 |
| Failed automated checks | 2 |
| Research publication records | 137 |
| Research feeds | 14 |
| Official edition-page monitors | 6 |
| Standards/release watch cards | 12 |
| Learning paths / checklist steps | 6 / 24 |
| Full-text reader items | 21 |
| Items with publisher image metadata | 266 |

All **20 new research channels** responded successfully. The crAPI feed had no eligible entries in its configured retention window and correctly reports a healthy zero count. The existing New York Times Technology endpoint remained unavailable, and The Business Standard had incomplete verified publication dates; its previous usable entries were retained. Sources exposes both failures.

The initial standards observations are baselines, not newly announced releases. Repository releases and official edition-page markers remain separate. The WSTG release watcher correctly prefers observed version 4.2 over an older 4.0 entry edited more recently. The GenAI announcement feed and official edition page are retained as separate evidence when they identify different editions.

The live check used the explicitly configured trusted HTTP CONNECT proxy required by this environment. TLS verification remained enabled. GitHub-hosted collection, public-source availability and future page layouts can differ; failures remain visible and validated prior records are retained.

## Previous relevance-fix baseline — 2.0.1

### Newsboard relevance fix — 30 October 2026

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
