# Upgrade to CyberWatch 2.0.1

This is a complete replacement project. It preserves the existing incident feed, newsletters, Bangladesh view, watchlist, refresh API, scheduled collection and hosting options, and adds Newsboard, additional advisory sources and the article reader.

## Relevance fix for an existing 2.0.0 installation

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
- Full article fetching is policy-controlled, bounded and cached. Most world-news publishers start with excerpts, images where available and original links. Enabling full text requires permission for that source and its exact HTTPS host allowlist.
- Networks requiring a trusted HTTP CONNECT proxy can set `CYBERWATCH_HTTPS_PROXY=http://approved-proxy:3128`. Direct HTTPS is the default. Proxy credentials and HTTPS/SOCKS proxy transport are not supported; TLS verification stays enabled. The proxy must enforce public destinations and its own DNS policy.

## Verify the installation

```bash
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/*.test.mjs
python scripts/validate_data.py
```

On Linux/macOS, `npm run check` also runs JavaScript syntax checks and these validations. No npm packages are required. For a local static preview, use `python -m http.server 8000 --directory dist`.
