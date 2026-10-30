# Change log

## 2.0.1 — 30 October 2026

- Fixed automatic Newsboard inclusion of every item from security-focused publishers. Each news article now needs a relevant subject in its title or bounded publisher lead.
- Excluded consumer tracking/consent disputes and unrelated business/technology reporting while retaining data-breach settlements and other genuine cybersecurity coverage.
- Applied the decision to retained and failed-source fallback records and added a browser fallback for older runtime/static snapshots.
- Prioritized relevant stories before per-source record limits; retained broader publisher updates in Newsletters.
- Shared the relevance policy between Python and JavaScript and added regression coverage for the reported GM headline, real threats, stale keywords, metadata boundaries, source budgets and cross-language parity.

## 2.0.0 — 30 October 2026

- Added a separate Newsboard navigation item and responsive news cards, including a mobile navigation bar that accommodates all six views.
- Added world-press, cybersecurity and advisory scopes, topic buttons, source/date/search filters and publisher attribution.
- Added BBC Technology, World and Business and other international news channels, including configured Washington Post endpoints with explicit failure reporting when unavailable.
- Added a local JSON source catalogue, keyword inclusion/exclusion settings, URL validation and bounded retention.
- Added official NGINX, Python, GitLab and Node.js security sources, with dated vendor evidence and conservative classification.
- Added a plain-text Article detail tab, source images, captions, availability labels, original links, bounded extraction and source-controlled full-content policies.
- Preserved publication dates, reported-claim distinctions, stale-source indicators, source evidence, existing reviewed records, watchlists and the 30-minute refresh schedule.
- Increased record and payload budgets and refresh timeouts to accommodate the larger catalogue and reader content.
- Added regression checks for keywords, vendor adapters, retention, fair record budgets, article parsing, hostile content, safe network fetching and reader/UI normalization.

See README.md for source configuration and UPGRADE.md for installation steps and content-availability limits.
