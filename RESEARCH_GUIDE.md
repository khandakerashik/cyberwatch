# Research Lab

Research Lab is a separate workspace for official security publications, original research and practical learning. It shares CyberWatch's collector, source-health registry, reader and saved watchlist. Research records are deliberately excluded from the incident feed, Newsboard and Newsletters; saved research remains accessible in Watchlist.

## Standards Watch

Six official publication-page monitors cover OWASP Web Top 10, API Security Top 10, Mobile Top 10, LLM/GenAI Top 10, Agentic Applications Top 10 and the AI Testing Guide. Additional cards follow repository publications for WSTG, ASVS, MASTG, MASVS, API Security and MITRE ATT&CK data.

- **Edition watch** reads a specific official edition marker and relevant link. It does not hash the entire website, which would treat footer or navigation changes as publication changes.
- **Repository release** preserves the release title and link. It can describe software, datasets or project tooling; it is not automatically a new edition of a standard.
- **Published release**, **Prerelease**, **Draft** and **Release status unconfirmed** are distinct labels. A published repository item is not a guarantee that a standard is stable or final.
- **First observed** is when CyberWatch established a baseline. It is never substituted for an unknown publication date.
- **Source updated** means the feed supplied an update timestamp without a separate publication timestamp. Editing an old release does not make it a new standards version.
- **Change observed** means the edition/release marker changed relative to the retained observation. It does not claim the change was published at that check time.
- A failed check retains the last verified observation and displays an error. The previous successful check time remains visible.

Some publisher channels can disagree. For example, a project blog may announce an edition while its reference page still identifies an older edition. CyberWatch preserves each source's reported title and marker rather than silently resolving the disagreement.

Select **Follow source** to add a watch or research source to your browser-local following list. The **Following** selector narrows the corresponding view. It does not send notifications.

## Research Feed

The configured sources include official OWASP project feeds, PortSwigger Research, Google Project Zero, MITRE ATT&CK data, Trail of Bits, SpecterOps, Bishop Fox and official OWASP practice-lab releases. Eight further channels cover ZAP testing research, Doyensec, Microsoft Threat Intelligence, Check Point Research, ZAP releases, Sigma rules, garak and MobSF releases. The catalogue totals 22 feeds and six edition-page monitors. Broad company feeds require an article-level technical subject match.

Filter publications by domain, kind, offensive/defensive perspective, source, date and reading status. Topic labels use source defaults and explicit topic words. They are organizational aids, not authoritative OWASP or ATT&CK mappings. A publication about a technique does not establish that the technique is newly discovered.

**Read publication** opens the existing article reader. Available excerpts and publisher images retain their availability labels and original links. Full-text retrieval remains controlled by source policy; most research feeds provide excerpts. WSTG, ASVS, MASTG and MASVS release feeds have full feed text enabled with their verified CC BY-SA 4.0 attribution; this does not mean the complete standards documents are embedded. Publisher page fetching remains disabled for those four release channels.

**Mark reviewed** records your explicit review state. **Save** uses the existing Watchlist. **Export** includes the filtered research records and their domain, perspective and date-basis fields.

## Techniques library

The fourth tab contains 24 original, source-grounded study cards. Search and combine domain, level and study-status filters. Each card states its learning objective, a practical approach in an authorized lab, defensive validation, a common pitfall and direct primary-source references. Expand a card to work through its method, and mark it reviewed to keep a reading queue.

Topics include access control, session handling, SSRF, request parsing, cache boundaries, uploads, race conditions, business logic, GraphQL, OAuth, mobile storage/network/deep-link review, AI prompt and agent boundaries, cloud/identity review and detection validation. These are editorial study guides: the reviewed date is not a discovery date and a checkmark does not establish hands-on proficiency. New research publications remain in Research Feed with their actual source dates.

Reviewed technique IDs are browser-local alongside the existing research preferences. CSV export is available in Research Feed, not in the other three tabs.

## Learning Paths

Six editorial tracks cover:

1. Web and API assessment.
2. Mobile assurance.
3. AI and agent security.
4. Detection and purple teaming.
5. Cloud and identity boundaries.
6. Secure engineering and review.

Each track provides an objective, offensive practice, defensive validation, four checklist steps, official learning links and a personal notes field. Practice is framed around a controlled, authorized lab. Checkmarks are self-reported progress, not a certification or proof of competence.

Progress, followed sources, reviewed items and notes are stored in this browser under `cyberwatch.research.v1`. Watchlist selections retain their existing `sentinel.watchlist.v1` key. Clearing browser site data removes these preferences. Storage failures are reported as session-only changes. No account or cross-device synchronization is included.

## Collection and configuration

The administrator-controlled `data/research-sources.json` contains the feed catalogue and official page watches. The ordinary news source catalogue remains `data/news-sources.json`.

The same collection command refreshes all three streams:

```bash
python scripts/fetch_feeds.py
```

An alternate local research catalogue can be selected with:

```bash
python scripts/fetch_feeds.py --research-sources /path/to/research-sources.json
```

The live Python service and GitHub Actions workflow both use this collector. GitHub Pages continues to serve the published snapshot. Its **Reload snapshot** button does not execute Python; run the Actions workflow to request collection on demand.

New source definitions must use supported formats, bounded fields and public HTTPS endpoints. Edition watches use named adapters and exact allowed hosts. Adding a new publication layout requires an adapter and a parser fixture. An unrecognized layout fails visibly instead of inventing an edition.

The snapshot remains schema version 1 with optional `learning` metadata, research source groups and `researchWatch`. Older snapshots remain readable. A first upgraded collection populates the new channels and establishes watch baselines.

## Coverage limits

The catalogue is curated and extensible. It is not an exhaustive record of worldwide methods, every OWASP project or every standards change. Feed windows, bounded retention, source layout changes, network failures and editorial classification can affect coverage. Source health and original links remain part of the reading workflow.

See `ROADMAP.md` for durable release history, diffs, topic alerts, methodology mappings, lab evidence and a future authenticated team workspace.
