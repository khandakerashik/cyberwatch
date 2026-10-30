# CyberWatch improvement roadmap

## Product direction

CyberWatch should help a practitioner move from **what changed**, to **why it matters**, to **what to learn or validate next**. The public portal brings together cybersecurity reporting, official advisories, standards and original research. A future authenticated workspace can connect that public evidence to an organization's technologies, findings and assessment work.

Version 3.1.0 adds Source quality, Incident history and the Techniques library to the portal and Research Lab. The modules below are proposed future work unless explicitly marked delivered. Sequence them by information quality and practical value before adding more sources or automation.

## Delivered in 3.0.0

- A responsive cybersecurity portal with a consistent dark visual system, clear severity/source states, keyboard focus and reduced-motion support.
- Research Lab with Standards Watch, Research Feed and Learning Paths.
- Official OWASP edition-page watches and project-release feeds, including web, API, mobile, AI and agentic security; drafts and prereleases remain identified.
- Original research feeds from PortSwigger, Project Zero, Trail of Bits, SpecterOps and Bishop Fox, plus ATT&CK dataset updates and official practice-lab releases.
- Filters for security domain, publication kind, perspective, source, date and reading status.
- Source following, reviewed items, shared watchlist saving and research CSV export.
- Six study paths, each with offensive practice, defensive validation, four checklist steps, primary learning resources and personal study notes.
- Browser-local preferences and progress. The existing scheduled collection, news relevance rules, reader, source health, incident feed and Bangladesh views continue to work.

## Delivered in 3.1.0

- Green accents over dark charcoal surfaces across desktop and mobile.
- A Source quality dashboard with collection state, overdue-check detection, up to 48 actual historical checks, sample-based success rates, source freshness, retained record counts, reader coverage, filters and export.
- Incident history with a calendar, explicit reported-milestone versus publication-date modes, major/all scopes, search, record-type filters and evidence links.
- A searchable Techniques library with 24 practical, cited study cards and browser-local reviewed status.
- Eight additional verified research/tool feeds; expanded licensed OWASP release text; improved article completeness labels, extraction and cache handling.

## Phase 1 — Make relevance and change tracking dependable

### 1. Extend the delivered source quality dashboard

The operational dashboard is delivered. Next, add invalid-date/rejection telemetry, language/region/domain coverage and a reviewed relevance benchmark. Continue to track successful collection rate, time since last successful check, retained-record age, invalid-date counts, coverage by language/region/domain, and the number of source items rejected as irrelevant. Add a small reviewed set of relevant and irrelevant articles to evaluate filter changes.

**Useful outcome:** an analyst can tell whether a quiet feed means no relevant updates or a collection problem. Coverage becomes measurable; the product does not imply it sees every event worldwide.

**Acceptance checks:** failures are visible without discarding good data; source-level gaps are traceable; recurring false positives can be reproduced and fixed without weakening other topics.

### 2. Durable standards history and meaningful diffs

Store a history of observed official edition markers, release links, source dates and check dates. Add an explicit comparison of a new observation with the previous one. For versioned standards, show added, changed and retired requirements, with source identifiers and a human review state.

**Useful outcome:** a new ASVS, MASVS, WSTG or AI publication becomes a reviewable change record. An unrelated website edit or repository tooling release is not presented as a new standards edition.

**Architecture:** the current snapshot and Actions cache support bounded observations. Durable history needs a versioned object store, controlled repository history or a database; a disposable Actions cache is not an archive.

### 3. Topic subscriptions and a research digest

Extend the existing source follows with saved topic queries, a weekly publication digest and configurable delivery. Allow subscriptions such as mobile testing, AI agent security, API authorization, identity attacks and detection engineering. Deduplicate repeated reports and distinguish newly published material from newly observed material.

**Useful outcome:** fewer repeated checks and a focused reading queue. Delivery preferences should include cadence, quiet periods and a test-preview step. Email/chat delivery requires a configured integration; browser-local follows currently filter the portal only.

## Phase 2 — Connect intelligence to security work

### 4. Vulnerability workbench

Create a dedicated CVE page combining vendor evidence, affected products/versions, CVSS version/vector, CISA KEV status, EPSS score/date, available fixes and cited exploit evidence. Keep each field's provenance and timestamp. Allow watchlists for technologies such as NGINX, Python, GitLab, Node.js, PHP, Java and application frameworks.

**Useful outcome:** a consolidated review queue with enough context to assess exposure. Avoid merging different meanings into an unexplained risk number: severity, exploitation evidence, probability and local exposure are separate dimensions.

**Dependencies:** primary-source adapters, product/version normalization, explicit unknown values and correction handling. Consult official [CVE](https://www.cve.org/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/) and vendor records when implementing.

### 5. Extend incident history with durable cases and source comparison

The date-based page is delivered. Next, persist a durable archive beyond feed/cache retention and group reports that refer to the same event while retaining every publisher, publication date, original claim and correction. Show a concise timeline, affected entity, reported impact, attribution confidence and unresolved discrepancies.

**Useful outcome:** ten articles about one incident become one navigable case with ten pieces of evidence. Independent reporting remains distinct from a copied press release.

**Acceptance checks:** exact-URL deduplication remains separate from incident clustering; an analyst can split a wrong cluster; corrected figures do not erase the original reporting history.

### 6. Standards-to-test methodology library

The Techniques library provides an initial set of 24 cited practice guides. Next, build version-aware mappings between ASVS, MASVS, WSTG, API/AI guidance, CWE and appropriate ATT&CK techniques. Each test entry should state its objective, prerequisites, authorized scope, manual procedure, expected secure result, evidence, remediation and defensive verification.

**Useful outcome:** practitioners can turn a research publication into a repeatable test and a clear finding. Students can understand both the weakness and the control that prevents or detects it.

**Architecture:** mappings need editorial review and explicit source versions. A keyword match can suggest a mapping; it should not silently become an authoritative mapping.

### 7. Lab notebook and evidence workflow

Expand the current checklists and notes into exercises with hypotheses, environment versions, observations, screenshots/files, detection evidence, remediation and retest results. Add templates for web/API, mobile, cloud/identity, AI and purple-team work. Allow progress export/import before adding account synchronization.

**Useful outcome:** learning produces a reproducible record. Track reading, attempted practice, completed practice and independently reviewed evidence as separate states.

**Acceptance checks:** no automatic claims of proficiency; users can export their work; sensitive evidence is never included in the public news snapshot.

## Phase 3 — Add a private team workspace

### 8. Accounts, roles, collaboration and audit history

Introduce SSO/OIDC, workspace membership, reader/analyst/reviewer/admin roles, comments, assignment, review queues and an audit trail. Add a database with backups and clear retention rules.

**Useful outcome:** SOC, AppSec and infrastructure teams can review and act on the same evidence. Private organization context belongs in an authenticated service; the public GitHub Pages portal can remain the public intelligence frontend.

### 9. Asset relevance and findings correlation

Import technology inventories and supported scan/SBOM formats, then match advisories to actual products and versions. Useful adapters may include Nessus/Tenable exports, CycloneDX/SPDX, dependency findings and API/application inventories. Preserve the original scanner evidence and record the analyst's applicability decision.

**Useful outcome:** prioritize a Python or NGINX advisory because a matching exposed service exists, rather than because the headline sounds urgent. Add ownership, business criticality, remediation status and retest dates.

**Dependencies:** authenticated storage, reliable version comparison, import validation and identity/role controls. Incorrect product matches must remain reviewable.

### 10. Detection engineering workspace

Link researched behaviors to required telemetry, reviewed Sigma/YARA rules, lab validation results and detection coverage. Record rule compatibility, test data, false positives, expected signals and operational limitations. Offer controlled export to the user's existing detection workflow.

**Useful outcome:** offensive research improves defensive visibility. A rule is described as tested only when the workspace contains actual test evidence.

## Phase 4 — Add assisted analysis with traceable evidence

### 11. Source-grounded research assistant

Answer questions over collected publications and approved internal material, with direct citations and dates. Suggested uses include comparing standards editions, summarizing what a paper changes, drafting a study plan and proposing test/checklist mappings for review.

**Acceptance checks:** access controls are enforced by the application, retrieved content is treated as untrusted data, answers expose conflicting evidence, and unsupported conclusions are marked unknown. Keep analyst approval for saved assessments and downstream actions.

### 12. Multilingual coverage and international source expansion

Add evaluated language-specific relevance rules, retain original-language titles, and distinguish translations from source text. Expand regional CERTs, national authorities and original researchers in measured batches. Track which regions and languages are represented.

**Useful outcome:** broader worldwide awareness without concealing coverage gaps or turning translations into unsupported claims.

## Recommended implementation order

| Order | Next deliverable | Why this comes first |
| --- | --- | --- |
| 1 | Source quality dashboard + durable standards history | Establish dependable observations and explain collection gaps. |
| 2 | Saved topic queries + previewable weekly digest | Reduce repeated manual monitoring using the existing source catalogue. |
| 3 | CVE workbench + technology subscriptions | Improve daily vulnerability triage without requiring private inventory imports. |
| 4 | Methodology library + notebook export/import | Turn reading into reusable assessment and learning work. |
| 5 | SSO, database and team review workflow | Provide the foundation for sensitive organizational context. |
| 6 | Asset correlation + detection validation | Connect intelligence to exposure and observable defensive outcomes. |
| 7 | Grounded assistant + evaluated multilingual expansion | Scale analysis after provenance and review are dependable. |

## Practical success measures

- Time from source publication to collection, reported separately from detection of a page change.
- Source availability and age of retained data.
- Analyst-reviewed relevance precision and known missed-publication cases.
- Duplicate reports per incident and incorrect cluster merges.
- Standards changes reviewed and methodology updates completed.
- Research items reviewed, lab exercises documented and retests performed.
- Findings or advisories matched to verified assets, with analyst confirmation.
- Detection tests with actual telemetry and documented false-positive findings.

These are proposed product measures, not results already achieved by version 3.1.0.
