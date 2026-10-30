# Upgrade to CyberWatch 3.1.0

This is a complete replacement project. It preserves the existing incident feed, newsletters, Bangladesh view, watchlist, refresh API, scheduled collection and hosting options, and adds the green portal theme, Source quality dashboard, Incident history and expanded Research Lab. The earlier Newsboard, advisory sources, reader and relevance fix remain included.

## Upgrade the existing GitHub Pages repository

This release is a complete replacement archive for `khandakerashik/cyberwatch`. Extract it and upload all contents into the existing repository root on `main`, replacing matching files and adding new files. The website URL remains `https://khandakerashik.github.io/cyberwatch/`.

Include `.github`, `dist`, `data`, `scripts`, `server` and `tests`. Research Lab requires `dist/research-core.js`, `dist/research-ui.js`, `dist/portal.css`, `data/research-sources.json` and `scripts/research_sources.py` along with the updated application and validation files. Source quality and Incident history also require `dist/insights-core.js`, `dist/insights-ui.js` and `scripts/source_health.py`. Keep any custom curated records and API/CSP configuration when merging the update.

Keep **Settings → Pages → Source → GitHub Actions**. The commit starts **Refresh intelligence and deploy Pages**. Wait for both `build` and `deploy`, then use Ctrl+F5 and open **Source quality**, **Incident history** and **Research Lab → Techniques library**. A manual run from Actions also starts a fresh collection. The included cron is `18,48 * * * *`, matching the existing repository's observed timing. A separate `schedule-test.yml` heartbeat can remain; it does not deploy the site.

The new collector re-evaluates retained records and establishes official-watch baselines. Clearing the Actions cache is not required. Existing caches seed source history from their recorded last attempt; future checks append real observations up to 48 per channel. Existing browser watchlists keep the same key. New reading preferences, progress and notes use a separate browser-local key. A live Python installation retaining an older runtime snapshot gets Research Lab data at its next successful refresh.

## Included relevance fix for an existing 2.0.0 installation

Deploy the complete replacement project, preserving your runtime directory and local configuration as described below. Include the new `dist/news-relevance.js`, `dist/news-relevance-rules.js`, `data/news-relevance-rules.json` and `scripts/build_relevance_rules.py` files. Restart the Python service and hard-refresh the browser (Ctrl+F5 on Windows) so it loads the new frontend modules.

Newsboard immediately reassesses older snapshots that do not contain relevance decisions. The next regular or manual publisher refresh stores the new decisions and prioritizes relevant articles in source budgets. GitHub Pages installations should deploy the updated files/workflow and reload the page. The broader Newsletters view continues to show publisher updates; the stricter gate applies to Newsboard.

## Existing Python installation

1. Stop the running CyberWatch service.
2. Back up your current project and its `runtime/` directory or configured `CYBERWATCH_DATA_DIR`. Preserve any customized `data/curated.json`, `data/bangladesh-curated.json`, API configuration, service configuration and environment variables.
3. Extract this archive into the project directory. Merge your local curated-data changes into the bundled files if applicable. Keep your current runtime snapshot; legacy snapshots remain readable.
4. Install the pinned dependency and start the service from the project root:

   ```bash
   python -m pip install -r requirements.txt
   python -m server.app
   ```

5. Open `http://localhost:8000`, refresh the browser page, select **Newsboard** under **WORKSPACE**, and click **Refresh**. This first collection adds the new source registry and records to an existing runtime snapshot. A collection can take several minutes; the interface reports completion and source failures.
6. Inspect **Sources** for endpoint failures. A configured source with no available matching records may have a healthy zero count; a failed endpoint is explicitly marked.

The 30-minute automatic collection schedule resumes while the service is running. Existing watchlist IDs are retained in the browser. Newly collected records are public-source reporting and should be checked against their original publications before operational decisions.

## GitHub Pages

Upload the extracted contents, including `.github`, `data`, `scripts`, `tests` and `dist`. Preserve any custom API endpoint in `dist/config.json`; if necessary, re-run `python scripts/configure_api.py https://YOUR_SERVICE/` to set both the endpoint and its CSP rule. Run the **Refresh intelligence and deploy Pages** workflow, then reload the website. Pages-only installations use **Reload snapshot**; this downloads the last published snapshot and does not start Python in the browser.

## Docker or Render

Rebuild/redeploy from the updated source and retain the existing persistent volume/disk. The included service remains a single process/instance. The Render blueprint still selects a paid Starter service and persistent disk; no service has been purchased or deployed as part of this project update.

## New settings and limits

- `data/news-sources.json` is the administrator-managed catalogue for additional feeds, overrides, disabled sources and extra keyword phrases.
- The default collection budget is **1,200 records**, with a configurable maximum of **2,000**. Collection distributes a constrained budget across sources and retains bounded source history.
- The live collector has a **300-second** deadline. The browser allows **330 seconds** for a refresh job; a failed or invalid collection preserves the previous valid snapshot.
- Snapshots are limited to **32 MiB** in the server and browser. Individual publisher responses and reader text have separate smaller limits.
- Full article fetching is policy-controlled, bounded and cached. `allowPageFetch: false` permits licensed full feed bodies without enabling publisher-page requests. Complete cached content survives temporary failures only for the same publication version and permitted source policy. Most world-news publishers start with excerpts, images where available and original links. Enabling full text requires permission for that source and its exact HTTPS host allowlist.
- Networks requiring a trusted HTTP CONNECT proxy can set `CYBERWATCH_HTTPS_PROXY=http://approved-proxy:3128`. Direct HTTPS is the default. Proxy credentials and HTTPS/SOCKS proxy transport are not supported; TLS verification stays enabled. The proxy must enforce public destinations and its own DNS policy.

## Verify the installation

```bash
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/*.test.mjs
python scripts/validate_data.py
```

On Linux/macOS, `npm run check` also runs JavaScript syntax checks and these validations. No npm packages are required. For a local static preview, use `python -m http.server 8000 --directory dist`.
