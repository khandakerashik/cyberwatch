# Source quality and Incident history

Both pages work in a static GitHub Pages deployment and in the Python live service. They read the same validated snapshot as the rest of CyberWatch.

## Source quality

Open **WORKSPACE → Source quality** to inspect collection health and reader availability. Search by publisher/project or error text, filter by collection and state, and sort by attention, source name, record count or full-text coverage. Expand **Details** to see the last successful check, the recorded history window, the current error and source links. **Export CSV** includes the filtered sources and the underlying counts.

The dashboard measures observable operations:

| Measure | Meaning |
| --- | --- |
| Healthy | The latest automated attempt succeeded and a check was recorded within two hours. |
| Fetch error | The latest automated collection failed. Previously usable records are retained where available. |
| Check overdue | No attempt has been recorded for more than two hours, equivalent to four expected 30-minute intervals. An errored channel can also be overdue. |
| Reviewed manually | Curated records with no automated feed uptime claim. |
| Recorded success rate | Successful checks divided by actual recorded checks, with the sample count shown. Each channel retains up to 48 checks. |
| Records | Records retained in the current snapshot after source retention, deduplication and display budgets. Zero can be a healthy result. |
| Reader coverage | Full source text, excerpts, publisher restrictions and source/context-only records, calculated from those retained records. |

The upgrade seeds legacy sources from their explicitly recorded last attempt where possible. It does not reconstruct missing runs or fabricate historical uptime. Reloading the browser does not add a source check. A repeated assembly of the same attempt replaces that observation. Source histories are bounded and travel with the snapshot; an Actions cache reset or old snapshot restoration affects the available history.

The measures do not establish publisher credibility or independent verification of every reported claim. No composite trust score is invented. A slow-publishing standards project is not considered broken merely because its latest release is old: collection freshness and publication freshness are separate.

## Incident history

Open **WORKSPACE → Incident history**. The initial month contains the latest matching recorded milestone. Use the month field or arrows, select a day, or select **Show whole month**. **Jump to latest record** uses the current filters. Search across titles, organizations, CVEs, publishers and milestone descriptions. Calendar arrow keys move between dates.

Two date modes are available:

- **Reported milestones** shows explicit dated entries from reviewed timelines, such as detection, disclosure, a patch or a notification. A feed publication is not converted into an inferred attack date.
- **Publication dates** shows source publication/disclosure dates for the wider cybersecurity stream. CISA KEV dates are labelled as catalog-addition dates. These dates may be later than the underlying incident.

The **Major events** scope includes incident records, high/critical assessments and explicit reported exploitation. It does not turn unscored news headlines into independently assessed major incidents. Select **All cybersecurity records** in publication mode to include wider relevant reporting. Research/learning publications remain in Research Lab, and the Newsboard relevance rules also exclude unrelated news from this history.

Timestamped records are grouped in **Asia/Dhaka (BDT, UTC+06:00)**. Date-only source values keep the original calendar date. A record can have several milestones on different dates; counts state whether they represent milestones, publications or distinct records.

Each entry opens the existing detailed record and links to its original evidence. History CSV includes the date basis, original source date value, displayed calendar date, milestone and evidence URLs. Export includes all matching entries for the selected day/month, including entries beyond the on-screen pagination limit.

This page navigates the records that CyberWatch has retained. Curated records persist; automated news follows its configured retention window. It is not a durable exhaustive archive of all worldwide incidents. A future versioned archive and incident clustering are documented in `ROADMAP.md`.

## Reading complete and partial articles

The reader shows its availability state before the content and a continuation notice after incomplete text. Word count and collection timestamps describe the available content. Images remain publisher-hosted metadata with source attribution; they can become unavailable independently of the text.

Version 3.1 fixes unnecessary shortening of permitted content, preserves plain-text paragraphs, supports more article-body structures and retains a complete same-version copy through temporary collection failures. A changed publication or source policy cannot reuse an inappropriate old full copy. Full text remains bounded and available only for sources whose configured policy permits it.

The TeamViewer example from The Hacker News illustrates a publisher-feed limit: its RSS description contains 394 characters and no full body. The source description ends mid-sentence. It is now clearly labelled partial and ends with an ellipsis; the original-publication link opens the complete publisher report. The current source configuration does not assert permission to republish that entire news article.

Four OWASP project release feeds—WSTG, ASVS, MASTG and MASVS—now retain their available licensed full feed text with CC BY-SA 4.0 attribution. This is release-note content, not the complete standards documents. Other licensed sources continue to support full-text collection. General news feeds can still provide only excerpts.

Administrator configuration distinguishes two settings:

```json
{
  "articlePolicy": {
    "allowFullText": true,
    "allowPageFetch": false,
    "allowedHosts": ["github.com"],
    "license": "Use the verified source license and required notices here.",
    "attribution": "Original project contributors"
  }
}
```

`allowPageFetch: false` keeps permitted full feed content without fetching publisher pages. Page fetching, when enabled for an appropriate source, uses exact hosts, robots checks, bounded requests, caching and plain-text extraction. Source policies belong in administrator-controlled catalogue files, never in user-supplied reader URLs. See `THIRD_PARTY_NOTICES.md` for the enabled source notices.

## Data compatibility

The snapshot remains `schemaVersion:1`. Optional `sources[].collectionHistory` contains up to 48 ordered observations with `at`, `status` and `recordCount`. Optional article fields include `availabilityReason`, `truncated`, `retained` and `lastAttemptAt`. Older snapshots remain readable. Health and attempt timestamps do not by themselves advance the content-update timestamp.
