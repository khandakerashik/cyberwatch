# CyberWatch — Cyber Incident Console

A terminal-inspired threat intelligence console for incident reports, exploited vulnerabilities, security advisories, patch updates, publisher news, and Bangladesh-specific cyber activity. Open an event to read its description, severity rationale, impact, recommended actions, technical context, timeline, and original sources.

**Version 1.4.0** adds a persistent viewport footer, expanded event assessments, and headline-filtered Bangladesh English newspaper coverage. The always-on Python/Waitress service checks publishers every **30 minutes** and starts an on-demand check when a visitor selects **Refresh**. The HTML, CSS, and JavaScript console and its refresh API can run together on one host. No database service or publisher API key is required.

GitHub Pages remains available as a static deployment: GitHub Actions collects and publishes a snapshot on a best-effort 30-minute schedule. Pages can also connect to the live service to provide on-demand collection. The deployment sections below explain each setup.

## Console views

- **Incident feed:** incident reports, vulnerabilities, advisories, and patches, with search, severity/date filters, detailed assessments, and source evidence.
- **Newsletters:** public updates from Cybernews, BleepingComputer, SecurityWeek, Help Net Security, The Hacker News, Palo Alto Networks Unit 42, CrowdStrike, PHP, Microsoft Security, Cisco Talos, and Bangladesh publishers. Browse by publisher and open an item for its available feed excerpt and original article link. Cybernews entries show the headline, publication date, attribution, and link. This view aggregates public RSS/Atom and publisher-index content; it does not subscribe users to emails or read an inbox.
- **Bangladesh:** national advisories, reported local cyber activity, and defensive programmes from BGD e-GOV CIRT, Bangladesh Cyber Security Intelligence, and reviewed records, plus English newspaper headlines containing “cyber”. Newspaper sources include The Daily Star, Dhaka Tribune, The Business Standard, and The Financial Express. Use **News coverage** and the publisher filter to browse newspaper updates. Scope labels distinguish publisher coverage from national advisories and reported local activity.
- **Watchlist and Sources:** save records in this browser and inspect each publisher's latest attempt, last successful collection, and any collection error.

The freshness display separates a changed database from a collection attempt and from this browser's snapshot retrieval. Exact times are displayed in **Asia/Dhaka (BDT, UTC+06:00)**. The stored source dates retain their original precision; a date-only publication is not given an invented time.

## Responsive interface

CyberWatch uses a dark cyber-tech interface with a fine background grid, restrained mint accents, terminal-inspired panels, and an eagle logo. The interface reflows from compact phones to wide desktop monitors:

- **Phones:** full-width content, five labeled bottom-navigation buttons, stacked event cards, wrapping filters, and safe-area spacing for device cutouts and home indicators.
- **Tablets:** a compact icon sidebar, flexible card grids, and readable search and filter controls.
- **Desktop and wide screens:** a full sidebar, incident table, and adjacent intelligence panels within a bounded content width.
- **Event details:** the heading and content share a scrollable area, while the close controls remain available, including on short landscape displays.

Main navigation and primary touch controls have targets of at least 44 CSS pixels. Keyboard navigation, visible focus, and reduced-motion preferences are supported. The footer credits **Khandaker Ashikul Hoque** and stays fixed to the bottom of the viewport as content scrolls. On phones it sits directly above the bottom navigation. Reserved space follows the measured footer and navigation heights so the final content and controls remain reachable, including when text wraps. Event dialogs retain their own fixed action bar and independently scrollable content.

## Expanded event details

The three detail tabs remain **Overview**, **Timeline**, and **Sources & evidence**. They now include:

- **Technical context**, when reviewed source material is available: affected systems and versions, entry point, prerequisites, and source-described mitigation. The bundled PHP, CAPCOM ID, Railway, and Node.js assessments include this additional context.
- **Detection and triage**, explicitly labeled as an analyst review checklist, with evidence limitations and unconfirmed details listed separately. Missing versions, indicators, affected counts, or attack methods are left unknown.
- **Record and source freshness**: original publication, record update, source-channel name, latest collection attempt, latest successful collection, and collection errors. Curated records are identified as reviewed inputs and do not receive invented fetch times.
- **Official CVE lookup links** for valid CVE identifiers, plus related records with an explicit relationship such as a shared CVE. A relationship is a navigation aid, not a claim that separate reports describe the same incident.
- **Publisher context** for news: reported relevance, follow-up guidance, original article links, and evidence limits. Bangladesh newspaper coverage describes the publisher channel, not necessarily the location of an attack or victim.

**Copy brief** includes the available technical context, evidence qualifications, original sources, CVE links, and source-channel freshness. The same detail layout works for automated records; where the collected source does not supply reviewed technical information, the panel says so instead of creating it.

## Deploy from GitHub

### Put the project in a repository

1. Extract the project ZIP. The repository root must contain `dist`, `data`, `scripts`, `server`, `tests`, `.github`, `requirements.txt`, `render.yaml`, `Dockerfile`, and this README. Upload the extracted contents, **not the ZIP file**. Include the `.github` directory; it contains the validation and Pages workflows.
2. Create a GitHub repository, such as `cyberwatch`, with `main` as its default branch.
3. Upload all project contents to that repository. You can use **Add file → Upload files**, GitHub Desktop, or Git:

   ```bash
   git init -b main
   git add .
   git commit -m "Create CyberWatch cyber incident console"
   git remote add origin https://github.com/YOUR_USERNAME/cyberwatch.git
   git push -u origin main
   ```

### Full application: Render with automatic and manual collection

The included `render.yaml` selects a **paid, always-on Starter web service and a 1 GB persistent disk**, with one service instance. Review Render's charges before creating the service. A sleeping service cannot keep an unattended 30-minute collection schedule. This configuration is provided for you to deploy; including it in the project does not create a hosting account or purchase a service.

1. Create a Render Blueprint from your GitHub repository, using the root `render.yaml` file. Review the service and disk configuration, then deploy it.
2. The native Python service uses the included `.python-version` to select Python 3.13, installs `requirements.txt`, and starts `python -m server.app --host 0.0.0.0`. It serves both the console and the refresh API through Waitress.
3. Open the service's HTTPS URL after its health check succeeds. Leave `dist/config.json` at its default `"apiBase": "auto"`; the console discovers the API on the same origin. GitHub Pages is not required for this setup.
4. Select **Refresh** to start a publisher check. The console shows the running job, waits for collection to finish, and loads the resulting snapshot. Automatic checks continue every 1,800 seconds while the service is running.

The disk is mounted at `/var/data`, and `CYBERWATCH_DATA_DIR=/var/data/cyberwatch` preserves the last valid snapshot across restarts and deployments. On startup, the service uses its stored snapshot or seeds one from `dist/data/incidents.json`; it starts a check when the previous check is due. Keep **one instance and one server process** because refresh coordination and job status are held in that process. Waitress handles concurrent HTTP requests with threads.

Official references: [Render Blueprints](https://render.com/docs/infrastructure-as-code) · [Persistent disks](https://render.com/docs/disks).

### Full application: Docker on an always-on host

The separate Dockerfile runs the same application on Python 3.13. From the repository root:

```bash
docker build -t cyberwatch .
docker volume create cyberwatch-data
docker run --detach --name cyberwatch --restart unless-stopped --publish 8000:8000 --mount type=volume,source=cyberwatch-data,target=/app/runtime cyberwatch
```

Open **http://localhost:8000**. The named volume retains the live snapshot at `/app/runtime/snapshot.json`. The container runs as UID **10001**; a host bind mount used instead of the named volume must be writable by that user. Run a single container instance. For public HTTPS behind a reverse proxy, set `CYBERWATCH_PUBLIC_ORIGIN` to the exact public origin, such as `https://cyberwatch.example.com`.

### GitHub Pages: scheduled snapshots

1. Choose a GitHub account/repository plan that supports Pages. In the repository, open **Settings → Pages** and set **Build and deployment → Source** to **GitHub Actions**.
2. Open **Actions → Refresh intelligence and deploy Pages → Run workflow**, select `main`, and run it. This also retries an initial push that ran before Pages was enabled.
3. Wait for the `build` and `deploy` jobs to succeed. Open the URL shown in the deployment or in **Settings → Pages**. The usual project URL is `https://YOUR_USERNAME.github.io/cyberwatch/`.

The workflow runs on pushes to `main`, on manual workflow dispatch, and at minute **17 and 47 of every hour in UTC** (`17,47 * * * *`). GitHub scheduling is best effort, and collection and deployment take additional time. For a differently named default branch, change the branch filters in both files under `.github/workflows/`.

With Pages alone, the dashboard button is **Reload snapshot**. It downloads the latest published data; Pages cannot run the Python collector in response to a browser click. To request collection from this setup, run the workflow in the repository's Actions tab. Use the next section to add immediate on-demand collection to a Pages-hosted console.

GitHub Pages commonly serves a public website even when its source repository is private. Use only information appropriate for the configured audience; this project contains public intelligence. Enterprise access controls depend on the repository and account configuration. See GitHub's [Pages access-control documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/changing-the-visibility-of-your-github-pages-site).

### Optional: GitHub Pages with the live refresh API

First deploy the always-on service above. Then configure the Pages console with the service's **application base URL**, including its trailing slash:

```bash
python scripts/configure_api.py https://YOUR_SERVICE.onrender.com/
```

The helper updates **both** `dist/config.json` and the `connect-src` rule in `dist/index.html`'s Content Security Policy. Commit and deploy both files. Supply the application base, **not `/api`**; the client appends `api/status`, `api/refresh`, and `api/snapshot` itself.

On the live service, set `CYBERWATCH_ALLOWED_ORIGINS` to the Pages site's exact origin, for example:

```text
https://YOUR_USERNAME.github.io
```

An origin contains the scheme and host, plus a port if applicable. Do not include the project path `/cyberwatch/`; wildcard origins are not accepted. For a custom Pages domain, use that exact origin instead. Multiple allowed origins can be comma-separated. Once configured, the Pages console uses **Refresh** to start collection on the service and loads its live snapshot.

To restore same-origin automatic discovery and its default CSP:

```bash
python scripts/configure_api.py --reset
```

### Server settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `CYBERWATCH_DATA_DIR` | `runtime/` under the project root | Writable directory for the live `snapshot.json`. Use persistent storage in a deployment; the Render blueprint sets `/var/data/cyberwatch`. |
| `CYBERWATCH_ALLOWED_ORIGINS` | Empty | Additional exact browser origins permitted to use the API. Same-origin use needs no entry. |
| `CYBERWATCH_PUBLIC_ORIGIN` | Unset | Exact public origin when a reverse proxy terminates HTTPS. Render's `RENDER_EXTERNAL_URL` is used automatically when this setting is absent. Otherwise the server uses the request's direct scheme and host. |
| `PORT` | `8000` | Listening port; `--port` overrides it. Hosted services should use `--host 0.0.0.0`. |

The collector cadence is 1,800 seconds. Concurrent refresh requests share the running job, and new jobs have a 60-second minimum interval between their start times. These controls are implemented in `server/app.py`; there is no multi-instance coordinator or external database.

### If the Pages deployment does not start

- Make sure `.github/workflows/pages.yml` is on the default branch and **Settings → Pages → Source** is **GitHub Actions**.
- If the repository is a fork, enable Actions and the scheduled workflow in its **Actions** tab.
- Check the workflow logs for a failed validation step. Invalid curated records deliberately stop publication.
- If a deployment is waiting for approval, review the `github-pages` environment's deployment protection settings.
- An organization policy may restrict GitHub Actions or Pages. The included workflow uses official GitHub Actions pinned to specific release commits.

Official references: [Configure a Pages publishing source](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site) · [Custom Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

## Run locally

From the project root, with Python 3.10 or newer, install the live server's one dependency and run the full application:

```bash
python -m pip install -r requirements.txt
python -m server.app
```

Open **http://localhost:8000**. Keep the process running for automatic collection. The default `runtime/` directory is local generated state and is excluded from Git. The application uses Waitress locally and in production; `python -m server.app --host 0.0.0.0` also allows access from other hosts on your network.

For a static preview with **Reload snapshot** only, using the default automatic API configuration:

```bash
python -m http.server 8000 --directory dist
```

On Windows, `py` can be used in place of `python`. Serve the directory over HTTP; opening `index.html` directly with `file://` prevents the browser from loading its JSON snapshot reliably.

To collect a new static snapshot when you have an internet connection:

```bash
python scripts/fetch_feeds.py
python scripts/validate_data.py
```

The collector and validation scripts use Python's standard library. Only the live server requires the package in `requirements.txt`; no npm installation is needed. All assets and the published snapshot are hosted with the application.

## How intelligence is collected

| Collection | Content | Handling |
| --- | --- | --- |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities CISA has identified as exploited | Uses CISA's [official GitHub mirror](https://github.com/cisagov/kev-data), with the CISA-hosted JSON as fallback. Date shown is **catalog addition**, not initial CVE publication. |
| [CERT-EU](https://cert.europa.eu/publications/security-advisories/) | Significant security advisories | Parses the official [security-advisory RSS](https://cert.europa.eu/publications/security-advisories-rss). |
| [Google Chrome Releases](https://chromereleases.googleblog.com/) | Stable-channel security fixes | Uses the blog's [HTTPS FeedBurner feed](https://feeds.feedburner.com/GoogleChromeReleases). Dev/beta announcements and stable releases with no explicit security-fix information are excluded. |
| [The Hacker News](https://thehackernews.com/) | Cybersecurity reporting | [Public RSS](https://feeds.feedburner.com/TheHackersNews); identified as secondary reporting. |
| [Cybernews](https://cybernews.com/) | Cybersecurity news and reporting | [Official RSS](https://cybernews.com/feed/). Shows the headline, publication date, attribution, and original link; article text is not reproduced. Identified as secondary reporting. |
| [BleepingComputer](https://www.bleepingcomputer.com/) | Security incidents, malware, and vulnerability reporting | [Official RSS](https://www.bleepingcomputer.com/feed/), with a brief feed excerpt and original link; identified as secondary reporting. |
| [SecurityWeek](https://www.securityweek.com/) | Cybersecurity industry and threat reporting | [Official RSS](https://www.securityweek.com/feed/), with a brief feed excerpt and original link; identified as secondary reporting. |
| [Help Net Security](https://www.helpnetsecurity.com/) | Security news, vulnerabilities, and research coverage | [Official RSS](https://www.helpnetsecurity.com/feed/), with a brief feed excerpt and original link; identified as secondary reporting. |
| [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/) | Threat research and incident analysis | [Unit 42 RSS](https://unit42.paloaltonetworks.com/feed/). |
| [CrowdStrike](https://www.crowdstrike.com/en-us/blog/) | Threat intelligence, research, and vendor updates | [Public blog RSS](https://www.crowdstrike.com/en-us/blog/feed). When an item supplies no summary, the console shows its headline and date and links to the original. |
| [PHP](https://www.php.net/) | Official announcements, security notices, and releases | [Official Atom feed](https://www.php.net/feed.atom). |
| [Microsoft Security](https://www.microsoft.com/en-us/security/blog/) | Threat intelligence, research, and security updates | [Security blog RSS](https://www.microsoft.com/en-us/security/blog/feed/). |
| [Cisco Talos](https://blog.talosintelligence.com/) | Threat research and Threat Source newsletter posts | [Public RSS](https://blog.talosintelligence.com/rss/). |
| BGD e-GOV CIRT [Advisories](https://www.cirt.gov.bd/advisories), [Alerts](https://www.cirt.gov.bd/alerts), and [Activities](https://www.cirt.gov.bd/news) | Bangladesh national guidance and institutional cyber activity | Separate source channels parse dated public index entries. Available titles and excerpts link to original pages; the collector does not claim to ingest complete articles or attached advisory PDFs. |
| [Bangladesh Cyber Security Intelligence](https://bcsi.gov.bd/) | Bangladesh-focused reporting and advisories | [Public RSS](https://bcsi.gov.bd/feed/). Automated coverage stays distinct from a reviewed local-incident assessment. |
| [The Daily Star](https://www.thedailystar.net/search?t=cyber#gsc.tab=0&gsc.q=cyber&gsc.page=1) | Bangladesh English newspaper cyber coverage | Discovers matching public headline links and verifies publication dates from the linked publisher pages. The supplied search page remains the source link; collection does not rely on its browser-only search results. |
| [Dhaka Tribune](https://www.dhakatribune.com/) | Bangladesh English newspaper cyber coverage | Filters the [official RSS](https://www.dhakatribune.com/feed/) by headline. |
| [The Business Standard](https://www.tbsnews.net/tags/cyber-attack) | Bangladesh English newspaper cyber coverage | Collects matching headings from the public **Cyber attack** topic index, then verifies publisher article metadata. |
| [The Financial Express](https://thefinancialexpress.com.bd/) | Bangladesh English newspaper cyber coverage | Collects matching headings from the public front page, then verifies publisher article metadata. |
| `data/curated.json` | Reviewed incident reports and detailed assessments | Edited in the repository. Each record links to its original source and distinguishes verified facts, reported claims, and analyst assessments. |
| `data/bangladesh-curated.json` | Reviewed Bangladesh advisories, reported incidents, and defensive activity | Maintains explicit Bangladesh scope, evidence limits, publication dates, and detailed assessments. |

There are **21 automated source channels and 2 reviewed inputs**. The three CIRT channels are collected separately. The collector merges these inputs, deduplicates stable IDs and matching article URLs within a stream, and prefers a detailed curated record when an automated item points to the same article. It keeps up to **300 records by default**, with bounded per-source collection, validates the result, and writes its output atomically. A direct collector run writes `dist/data/incidents.json`; the live server validates a staged result before publishing it as `snapshot.json` in `CYBERWATCH_DATA_DIR`. Different publications about the same CVE can remain separate events because their evidence, dates, or update types differ. An exploitation report and a patch release are intentionally distinct records.

The four English newspaper channels require a case-insensitive headline word starting with **cyber**, including **cybersecurity**, **cybercrime**, **cyberattack**, and **cyber-attacks**. A match only in an article body does not qualify. These channels display the headline, original publication date, attribution, and direct article link; they do not reproduce full articles or create automatic incident assessments. Collection is limited to the configured public feed or index, so it is not an exhaustive search of each newspaper's archive. A bounded history retains up to 20 matching headlines per newspaper for 30 days after publication as they rotate off an index. A valid feed or index with no current matches remains healthy. Failed or incomplete metadata checks retain the previous successful-collection time and report the failure instead of inventing dates.

All views use the same `events` array. Records use `stream: "intelligence"` for assessed security events and `stream: "news"` with `category: "News"` for publisher updates. News entries contain short public excerpts when available, retain original links, and use `severity: "unknown"`; a headline mentioning a critical flaw does not automatically turn a news post into a scored incident. A Bangladesh news item can appear in both the Newsletters and Bangladesh views without being stored twice.

The Pages workflow produces a deployment artifact; it does not commit generated feed changes back into the source repository. Its cached last collected snapshot supports outage recovery between workflow runs. If the cache is unavailable, the committed snapshot is the fallback. The live service retains its last valid snapshot in its data directory and uses it as the starting point for subsequent collections.

### Refresh and freshness

The full application automatically checks configured sources every **1,800 seconds / 30 minutes**. Selecting **Refresh** sends `POST /api/refresh`, starts a collection job immediately when idle and outside the cooldown, and returns its job ID. The browser polls that job's status, then downloads the new snapshot when it finishes. Publisher requests take time, so the button starts collection immediately while the updated results arrive after collection completes.

Concurrent requests reuse the active job. A new job cannot start within **60 seconds of the previous job's start**; the API returns a retry interval when that cooldown applies. A manual check does not postpone the regular automatic schedule. The server allows a collection up to three minutes before treating it as failed, and preserves the previous valid snapshot if the collector process or output validation fails. Individual publisher failures are recorded separately and retain that publisher's available previous records.

On **GitHub Pages alone**, collection is scheduled at minute **17 and 47 of every UTC hour**. The **Reload snapshot** button retrieves the last published result, and a manual run of **Refresh intelligence and deploy Pages** requests a new workflow collection. GitHub schedules can be delayed, and public-repository schedules can be disabled after 60 days without repository activity. See [scheduled workflow behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

In either deployment, an open, visible browser checks for a newly published snapshot every **60 seconds** and checks again when an overdue hidden tab becomes visible. This browser polling only downloads the existing snapshot; it is separate from the 30-minute publisher collector and does not advance feed-check timestamps by itself.

| Timestamp | What it means | What advances it |
| --- | --- | --- |
| **Database updated** — `databaseUpdatedAt` | Last change to the stored event content. Here, “database” means the public JSON dataset. | Added, removed, or changed normalized event records. A no-change check preserves this value. |
| **Last feed check** — `lastCheckedAt` | Most recent collector attempt to check publishers for updates. | A collector run, including one with individual source failures. Consult source status to see which checks succeeded. |
| `generatedAt` | Time this snapshot was assembled. | Snapshot generation; it does not establish new articles or success for every source. |
| **Browser snapshot retrieval time** | When this browser most recently loaded the published snapshot successfully. | Initial load, a successful manual retrieval, or a successful 60-second browser poll. This time alone does not establish that a publisher was checked again. |
| Source `lastAttemptAt` / `lastSuccessAt` | Attempt time and most recent successful fetch for one source. | Attempts advance the first; successful collection advances the second. |

Collection success and source publication dates are separate. A successful collection can return an older article. If a feed fails, its previous records and original successful-collection time are retained, and its source state becomes `error`. A fresh attempt timestamp therefore does not hide stale content. Curated reports are labelled as reviewed snapshots and do not acquire a fabricated live-collection timestamp.

The included download contains a snapshot that can be viewed immediately. Unattended collection begins when the live service is running, or when the scheduled GitHub workflow is installed and enabled. Deploying only `dist` to another static host does not transfer either collector schedule automatically.

## How to interpret events

- **Incident** describes a reported or confirmed security event. It is distinct from a vulnerability advisory or patch notice.
- **News** describes a publisher update or institutional activity. Its severity is unrated, and its publication does not by itself establish a security incident.
- **Severity** is either explicitly source-provided or identified as an analyst assessment in the detail view. CISA KEV records are **Unrated** because KEV does not supply a CVSS severity. Known exploitation alone does not assign a Critical score.
- **Confirmed** refers to the linked evidence for the stated event. It does not confirm compromise of your own environment or validate every third-party claim.
- **Known exploited** is used when the linked evidence establishes exploitation. It is not a claim that exploitation is ongoing against every affected deployment.
- For automated Chrome patch records, **Mitigated** means that a vendor update is available. Verify deployment in your own environment before closing a remediation task.
- Recommendations in automated feed records are labelled **Analyst guidance**; CISA's required action is attributed separately. Apply business context and review the vendor's exact instructions.
- Date-only values remain date-only when the source does not provide a precise timestamp. CISA-listed reference links have no publication date when the catalog does not supply one.

### Bangladesh scope

The Bangladesh view selects records with explicit Bangladesh geography or scope. It includes official national warnings about globally relevant software, local targeting or incident reporting, local defensive activity, and topic-filtered coverage from Bangladesh English newspapers. For newspaper records, Bangladesh identifies the publisher's regional channel; the story may concern events elsewhere. Presence in this tab is not a claim that a Bangladeshi organization was breached.

| `bangladeshScope` | Meaning |
| --- | --- |
| `national-advisory` | Nationally published guidance relevant to Bangladesh. A global vulnerability can belong here without a confirmed local victim. |
| `local-activity` | Reported Bangladesh targeting, incidents, or defensive programmes. The category and evidence note identify which kind of activity the record describes. |
| `coverage` | Bangladesh publisher coverage that has not been given a more specific reviewed local assessment. |

Older records retain their actual publication dates. Target lists, suspected attribution, and incomplete forensic findings remain qualified in their descriptions and evidence notes.

This is an intelligence reading and prioritization tool. It has no connection to internal assets, scanners, EDR, or ticketing systems. Watchlist selections are stored in the current browser; they are not shared between users or devices.

## Add or update an incident

Edit `data/curated.json` for global records or `data/bangladesh-curated.json` for reviewed Bangladesh records. Both contain JSON arrays. Copy an existing record, give it a unique stable `id`, and update its evidence and assessment. The source files are editable inputs; `dist/data/incidents.json` is generated output.

Use `sourceId: "curated"` for global curated records and `sourceId: "bangladesh-curated"` for Bangladesh curated records. For a Bangladesh record, include `"Bangladesh"` in `geography` and choose the appropriate `bangladeshScope`. Use `stream: "news"` and `category: "News"` for newsletter or institutional updates; otherwise use `stream: "intelligence"` and the relevant security-event category.

The following is a **schema example**, not a real incident. Replace every example fact and URL before adding a record:

```json
{
  "id": "example-incident-2026-10-23",
  "stream": "intelligence",
  "title": "Example incident title",
  "organization": "Example organization",
  "summary": "A concise, source-backed description of the event.",
  "description": "Verified facts, affected scope, and remaining uncertainties.",
  "category": "Incident",
  "severity": "high",
  "status": "investigating",
  "publishedAt": "2026-10-23",
  "updatedAt": "2026-10-23",
  "geography": ["Global"],
  "sectors": ["Technology"],
  "cves": [],
  "tags": ["Data exposure"],
  "impact": ["Describe the evidenced business or technical impact."],
  "recommendations": ["Describe a practical action and its relevant scope."],
  "timeline": [
    {
      "date": "2026-10-23",
      "title": "Initial disclosure",
      "description": "What the organization disclosed on this date."
    }
  ],
  "sources": [
    {
      "name": "Official disclosure",
      "url": "https://example.com/security-notice",
      "publishedAt": "2026-10-23",
      "kind": "primary"
    }
  ],
  "confidence": "confirmed",
  "severityBasis": "Analyst assessment: explain why this severity is appropriate.",
  "evidenceNote": "Explain uncertainty, the confirmed scope, and any unverified claim.",
  "sourceId": "curated",
  "exploited": false
}
```

Allowed values:

| Field | Values |
| --- | --- |
| `category` | `Incident`, `Vulnerability`, `Advisory`, `Patch`, `News` |
| `stream` | `intelligence`, `news`; missing legacy values default to intelligence |
| `bangladeshScope` | Optional: `national-advisory`, `local-activity`, `coverage` |
| `severity` | `critical`, `high`, `medium`, `low`, `unknown` |
| `status` | `investigating`, `active`, `mitigated`, `resolved`, `monitoring` |
| `confidence` | `confirmed`, `reported` |
| Source `kind` | `primary`, `secondary` |
| Dates | ISO date `YYYY-MM-DD` or an ISO datetime with an explicit timezone |

Preserve an existing event's `id` when updating it so saved watchlist references continue to work. Keep its original `publishedAt`, change `updatedAt`, and append a timeline entry and source for the new information. Do not change an event's status solely because a feed was fetched again.

### Optional reviewed technical context

Add a `technicalDetails` object when the linked sources support more detail. All fields are optional. Each list accepts up to 12 nonempty strings of up to 1,200 characters; `reviewedAt` accepts the same date formats as other record dates. The schema validator rejects unknown technical fields. The browser applies the same bounds before rendering or copying a brief.

| Field in `technicalDetails` | Content |
| --- | --- |
| `affectedSystems` | Source-supported products, systems, and affected version ranges. |
| `attackVector` | The disclosed entry point or technical mechanism, with uncertainty retained. |
| `prerequisites` | Configurations, privileges, or exposure conditions required for the reported issue. |
| `mitigation` | Source-described fixes and response measures. |
| `detection` | Practical analyst review steps informed by the evidence; these display as an analyst checklist. |
| `limitations` | Unconfirmed details, missing indicators, and limits on the reported scope. |
| `reviewedAt` | When this technical context was reviewed. It is distinct from the event's publication and a feed fetch. |

Omit unsupported facts. If a product version, CVE, indicator, attribution, or victim count is not established, say so in `limitations` or leave the relevant list empty. Add the supporting primary sources to the record's existing `sources` array.

Run the collector and validator, then commit the curated changes. A push to `main` runs the Pages collection and deployment workflow when Pages is configured. For the full application, deploy the new repository version to the service and select **Refresh**, or wait for its next scheduled check, to include the updated curated inputs in the live snapshot.

## Maintenance and validation

Python feed checks and schema validation:

```bash
python -m unittest discover -s tests -p "test_*.py"
python scripts/validate_data.py
```

With Node.js 20 or newer, also run the browser-logic checks:

```bash
node --check dist/app.js
node --check dist/refresh.js
node --check dist/footer.js
node --test tests/core.test.mjs tests/refresh.test.mjs
```

On Linux/macOS with `python3` available, `npm run check` runs the combined checks. `npm install` is unnecessary.

Tests cover unsafe URL handling, source HTML stripping, hostile XML rejection, date normalization, source outages, snapshot consistency, freshness timestamps, stream and Bangladesh filtering, and CSV formula-injection protection. Newspaper checks cover headline-only matching, publisher-host restrictions, missing-date handling, empty results, partial failures, and bounded history. Detail checks cover optional technical fields, CVE identifier validation, related-record relevance, and copied briefs. Server and refresh-client checks also cover job coalescing, cooldowns, atomic snapshot publication, origin validation, polling, and failure handling. Pull requests run offline validation without collecting feeds or deploying.

To change the record limit:

```bash
python scripts/fetch_feeds.py --limit 400
```

The CLI accepts limits from 1 to 500 and defaults to 300. Update the Pages workflow's collector command to retain an override in that deployment; the live server explicitly requests 300 in `server/app.py`. Add or adjust official feed endpoints in `SOURCES` inside `scripts/fetch_feeds.py`; feed formats need a matching parser. API keys and secrets must never be placed in `dist`, which is publicly downloadable on a public deployment.

## Project structure

| Path | Purpose |
| --- | --- |
| `dist/index.html` | Application entry point |
| `dist/styles.css`, `dist/updates.css`, `dist/responsive.css`, `dist/details.css` | Console theme, update views, responsive layouts, and expanded event details |
| `dist/app.js` | Browser rendering and interactions |
| `dist/core.js` | Filtering, sorting, source URL validation, exports |
| `dist/refresh.js` | API discovery, refresh requests, job polling, and snapshot retrieval |
| `dist/footer.js` | Measures the persistent footer and mobile navigation to reserve usable content space |
| `dist/config.json` | Same-origin discovery or an explicit live service base URL |
| `dist/cyberwatch-eagle.png` | CyberWatch eagle logo and browser icon |
| `dist/data/incidents.json` | Static published snapshot and initial live-service seed |
| `data/curated.json` | Reviewed incident content maintained in Git |
| `data/bangladesh-curated.json` | Reviewed Bangladesh advisories, incidents, and defensive activity |
| `scripts/fetch_feeds.py` | Public-feed and publisher-index collector, merge logic, and freshness metadata |
| `scripts/configure_api.py` | Sets a remote API base and the matching CSP origin, or restores automatic discovery |
| `scripts/validate_data.py` | Event and snapshot validation |
| `scripts/package_source.py` | Creates the portable project ZIP without Site identity or credentials |
| `server/app.py` | Waitress application, automatic scheduler, refresh jobs, API, and static serving |
| `requirements.txt` | Pinned live-server dependency; the collector uses the standard library |
| `.python-version` | Python 3.13 runtime selection for Render |
| `render.yaml` | Single-instance native Python deployment with paid Starter service and a 1 GB disk |
| `Dockerfile`, `.dockerignore` | Optional container deployment and its build exclusions |
| `runtime/snapshot.json` | Default live snapshot location, generated at runtime and excluded from Git |
| `tests/` | Offline Python and JavaScript regression checks |
| `.github/workflows/pages.yml` | Scheduled collection and Pages deployment |
| `.github/workflows/check.yml` | Pull-request validation |

Relative asset URLs allow the app to run under a GitHub Pages project subpath. There are no client-side tokens, third-party analytics, CORS proxy services, or runtime package CDNs.

## Portable source download

The **Download GitHub project** link in the information panel downloads `cyberwatch.zip`, containing the complete deployable project. The archive includes the application, bundled snapshot, curated input, collector, live server, deployment configuration, tests, and `.github` workflows. It excludes local Site identity, credentials, Git history, live runtime state, and the archive itself. The bundled snapshot reflects the packaged build; the running service may hold newer collected data. Run `python scripts/package_source.py` after changes to refresh this download; the Pages workflow also refreshes it before publication.
