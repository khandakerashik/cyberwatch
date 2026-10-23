import test from 'node:test';
import assert from 'node:assert/strict';
import { escapeHTML, safeURL, normalizeData, filterEvents, makeCSV, makeBrief, isNewsEvent, isBangladeshEvent, cveURL, relatedEvents } from '../dist/core.js';

const NOW = Date.parse('2026-10-23T12:00:00Z');
const event = (overrides = {}) => ({
  id: 'php', title: 'PHP session advisory', organization: 'PHP', summary: 'Patch session handling',
  description: 'A security update for session handling.', category: 'Vulnerability', severity: 'high',
  status: 'active', publishedAt: '2026-10-22T00:00:00Z', updatedAt: '2026-10-22T10:00:00Z',
  geography: ['Global'], sectors: ['Technology'], cves: ['CVE-2026-10000'], tags: ['Session'],
  impact: ['Application exposure'], recommendations: ['Apply the vendor update.'],
  timeline: [], sources: [{ name: 'PHP', url: 'https://www.php.net/releases/', publishedAt: '2026-10-22', kind: 'primary' }],
  confidence: 'confirmed', severityBasis: 'Analyst assessment; verify local exposure.', evidenceNote: '',
  sourceId: 'curated', exploited: false, ...overrides,
});
const envelope = (events, sources = []) => ({ schemaVersion: 1, generatedAt: '2026-10-23T10:00:00Z', sources, events });

test('source URL allowlist rejects script URLs, relative links, control characters, and embedded credentials', () => {
  for (const input of ['javascript:alert(1)', 'data:text/html,<script>', '//example.com', '/relative', 'https://user:pass@example.com', 'https://exa\nmple.com', 'https:\\example.com', null, 5]) {
    assert.equal(safeURL(input), '', String(input));
  }
  assert.equal(safeURL(' https://example.com/advisory?q=1&x=2 '), 'https://example.com/advisory?q=1&x=2');
  assert.equal(safeURL('http://example.com'), 'http://example.com/');
});

test('normalization validates envelope and dates, deduplicates IDs, and retains text without trusting HTML', () => {
  for (const input of [null, [], {}, envelope([], null), { ...envelope([]), schemaVersion: 2 }, { ...envelope([]), generatedAt: 'yesterday' }]) {
    assert.throws(() => normalizeData(input), TypeError);
  }
  const result = normalizeData(envelope([
    event({ title: '<img src=x onerror=alert(1)>', severity: 'CRITICAL', exploited: 'true',
      sources: [{ name: 'Unsafe', url: 'javascript:alert(1)' }, { name: 'Official', url: 'https://example.com' }],
      timeline: [{ date: 'invalid', title: 'No date' }, { date: '2026-10-22', title: 'Published' }],
    }),
    event({ title: 'Duplicate should not replace first' }),
    event({ id: 'invalid-date', publishedAt: '2026-02-31' }),
    event({ id: 'no-title', title: '' }),
  ], [{ id: 'curated', name: 'Verified reports', kind: 'curated', status: 'ok', itemCount: 999 }]));
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].title, '<img src=x onerror=alert(1)>');
  assert.equal(result.events[0].severity, 'critical');
  assert.equal(result.events[0].exploited, false);
  assert.equal(result.events[0].sources.length, 1);
  assert.equal(result.events[0].timeline.length, 1);
  assert.equal(result.events[0].timeline[0].date, '2026-10-22', 'Do not invent a midnight time for date-only evidence.');
  assert.equal(result.sources[0].itemCount, 1);
  assert.equal(escapeHTML(result.events[0].title), '&lt;img src=x onerror=alert(1)&gt;');
  assert.equal(escapeHTML(`'"&`), '&#39;&quot;&amp;');
  assert.deepEqual(normalizeData(envelope([])).events, []);
});

test('filters compose query, time, severity, category, source, and saved state', () => {
  const events = [
    event(),
    event({ id: 'critical', severity: 'critical' }),
    event({ id: 'old', publishedAt: '2026-09-01T00:00:00Z' }),
    event({ id: 'future', publishedAt: '2026-10-24T00:00:00Z' }),
    event({ id: 'unsaved' }),
  ];
  const result = filterEvents(events, {
    query: 'PHP CVE-2026-10000 global', severity: 'high', category: 'Vulnerability', period: '7d',
    source: 'curated', view: 'watchlist', savedIds: new Set(['php', 'critical', 'old', 'future']), now: NOW,
  });
  assert.deepEqual(result.map(item => item.id), ['php']);
  assert.equal(filterEvents(events, { query: 'not present', now: NOW }).length, 0);
  assert.equal(filterEvents(events, { source: 'php', period: '24h', now: NOW }).length, 0);
  assert.equal(filterEvents(events, { source: 'php', now: NOW }).length, 4);
  assert.equal(filterEvents(events, { view: 'watchlist', savedIds: ['php'], now: NOW }).length, 1);
});

test('sorts prioritize declared severity or update date without mutating input', () => {
  const events = [
    event({ id: 'low', severity: 'low', publishedAt: '2026-10-23T00:00:00Z' }),
    event({ id: 'critical', severity: 'critical', publishedAt: '2026-10-20T00:00:00Z' }),
    event({ id: 'unknown', severity: 'unknown', updatedAt: '2026-10-23T11:00:00Z' }),
  ];
  assert.deepEqual(filterEvents(events, { sort: 'severity', now: NOW }).map(item => item.id), ['critical', 'low', 'unknown']);
  assert.equal(filterEvents(events, { sort: 'updated', now: NOW })[0].id, 'unknown');
  assert.equal(filterEvents(events, { now: NOW })[0].id, 'low');
  assert.deepEqual(events.map(item => item.id), ['low', 'critical', 'unknown']);
});

test('CSV export escapes spreadsheet formulas after whitespace and quotes multiline content', () => {
  const csv = makeCSV([event({ title: '  =HYPERLINK("https://evil.example")', organization: '@SUM(1,2)',
    summary: 'Text with "quotes", commas\nand a second line.', impact: ['\t+1'],
  })]);
  assert.ok(csv.startsWith('\uFEFF"ID","Published at"'));
  assert.ok(csv.includes('"\'  =HYPERLINK(""https://evil.example"")"'));
  assert.ok(csv.includes('"\'@SUM(1,2)"'));
  assert.ok(csv.includes('"\'\t+1"'));
  assert.ok(csv.includes('"Text with ""quotes"", commas\nand a second line."'));
  assert.ok(csv.endsWith('\r\n'));
});

test('copied brief retains assessment caveat and safe primary sources', () => {
  const brief = makeBrief(event({ severity: 'unknown', sources: [
    { name: 'PHP', url: 'https://www.php.net/releases/' }, { name: 'Bad', url: 'javascript:alert(1)' },
  ] }));
  assert.match(brief, /Severity: Not assessed/);
  assert.match(brief, /Analyst assessment; verify local exposure/);
  assert.match(brief, /Apply the vendor update/);
  assert.match(brief, /https:\/\/www.php.net\/releases\//);
  assert.doesNotMatch(brief, /javascript:/);
});

test('database changes, collection attempts, and successful source fetches retain independent timestamps', () => {
  const result = normalizeData({
    ...envelope([event()]),
    generatedAt: '2026-10-23T18:00:00+06:00',
    databaseUpdatedAt: '2026-10-22T10:00:00Z',
    lastCheckedAt: '2026-10-23T11:59:00Z',
    sources: [{ id: 'curated', name: 'Publisher', kind: 'secondary', group: 'news',
      status: 'error', lastAttemptAt: '2026-10-23T11:59:00Z', lastSuccessAt: '2026-10-22T09:00:00Z',
      description: '<strong>Publication feed</strong>', url: 'javascript:alert(1)', error: 'Feed unavailable',
    }],
  });
  assert.equal(result.generatedAt, '2026-10-23T12:00:00.000Z');
  assert.equal(result.databaseUpdatedAt, '2026-10-22T10:00:00.000Z');
  assert.equal(result.lastCheckedAt, '2026-10-23T11:59:00.000Z');
  assert.equal(result.sources[0].lastSuccessAt, '2026-10-22T09:00:00.000Z');
  assert.equal(result.sources[0].lastAttemptAt, result.lastCheckedAt);
  assert.equal(result.sources[0].status, 'error');
  assert.equal(result.sources[0].kind, 'secondary');
  assert.equal(result.sources[0].group, 'news');
  assert.equal(result.sources[0].url, null);
  assert.equal(escapeHTML(result.sources[0].description), '&lt;strong&gt;Publication feed&lt;/strong&gt;');
});

test('legacy snapshots use recorded checks only, and invalid freshness values never become current time', () => {
  const legacy = normalizeData(envelope([], [
    { id: 'primary', lastAttemptAt: '2026-10-22T14:00:00Z' },
    { id: 'secondary', kind: 'secondary', lastAttemptAt: '2026-10-23T09:00:00Z' },
    { id: 'manual', kind: 'curated', lastAttemptAt: '2026-10-23T11:00:00Z' },
  ]));
  assert.equal(legacy.databaseUpdatedAt, legacy.generatedAt);
  assert.equal(legacy.lastCheckedAt, '2026-10-23T09:00:00.000Z');
  assert.equal(normalizeData(envelope([])).lastCheckedAt, null);
  for (const invalid of ['yesterday', '2026-02-31T12:00:00Z', '2026-10-23', null]) {
    const result = normalizeData({ ...envelope([]), databaseUpdatedAt: invalid, lastCheckedAt: invalid });
    assert.equal(result.databaseUpdatedAt, null);
    assert.equal(result.lastCheckedAt, null);
  }
  const dateOnlySource = normalizeData(envelope([], [{ id: 'undated-check', lastAttemptAt: '2026-10-23' }]));
  assert.equal(dateOnlySource.sources[0].lastAttemptAt, null);
  assert.equal(dateOnlySource.lastCheckedAt, null);
});

test('news publications stay separate from intelligence while watchlists support both streams', () => {
  const result = normalizeData(envelope([
    event({ id: 'intel' }),
    event({ id: 'headline', category: 'News', stream: 'intelligence', severity: 'unknown' }),
    event({ id: 'newsletter', category: 'Advisory', stream: 'news', sourceId: 'vendor' }),
    event({ id: 'unexpected', stream: 'unsupported' }),
  ]));
  assert.equal(result.events[0].stream, 'intelligence');
  assert.equal(result.events[1].category, 'News');
  assert.equal(result.events[1].stream, 'news');
  assert.equal(result.events[3].stream, 'intelligence');
  assert.ok(isNewsEvent(result.events[1]));
  assert.ok(isNewsEvent({ category: 'News' }), 'Legacy category-only publications remain news.');
  assert.equal(isNewsEvent(null), false);
  assert.deepEqual(filterEvents(result.events, { now: NOW }).map(item => item.id), ['intel', 'unexpected']);
  assert.deepEqual(filterEvents(result.events, { view: 'newsletters', now: NOW }).map(item => item.id), ['headline', 'newsletter']);
  assert.deepEqual(filterEvents(result.events, { view: 'newsletters', source: 'vendor', now: NOW }).map(item => item.id), ['newsletter']);
  assert.deepEqual(filterEvents(result.events, { view: 'watchlist', savedIds: ['intel', 'headline'], now: NOW }).map(item => item.id), ['headline', 'intel']);
});

test('Bangladesh filtering requires explicit geography or a declared scope, not incidental text', () => {
  for (const geography of [['Bangladesh'], [' bd '], ['বাংলাদেশ']]) assert.equal(isBangladeshEvent({ geography }), true);
  for (const geography of [[], ['BDT'], ['BDO'], ['United States'], 'Bangladesh']) assert.equal(isBangladeshEvent({ geography }), false);
  assert.equal(isBangladeshEvent({ bangladeshScope: 'national-advisory' }), true);
  assert.equal(isBangladeshEvent({ bangladeshScope: 'unsupported', title: 'Bangladesh in the headline' }), false);
  const events = normalizeData(envelope([
    event({ id: 'advisory', geography: ['Bangladesh'], bangladeshScope: 'national-advisory' }),
    event({ id: 'activity', geography: ['BD'], bangladeshScope: 'local-activity' }),
    event({ id: 'coverage', geography: ['Bangladesh'], bangladeshScope: 'coverage', stream: 'news', category: 'News' }),
    event({ id: 'global', geography: ['Global'], title: 'Bangladesh mentioned in a general publication', bangladeshScope: 'unsupported' }),
  ])).events;
  assert.equal(events[3].bangladeshScope, null);
  assert.deepEqual(filterEvents(events, { view: 'bangladesh', now: NOW }).map(item => item.id), ['activity', 'advisory', 'coverage']);
  assert.deepEqual(filterEvents(events, { view: 'bangladesh', regionScope: 'national-advisory', now: NOW }).map(item => item.id), ['advisory']);
  assert.deepEqual(filterEvents(events, { view: 'bangladesh', regionScope: 'local-activity', now: NOW }).map(item => item.id), ['activity']);
  assert.deepEqual(filterEvents(events, { view: 'bangladesh', regionScope: 'coverage', now: NOW }).map(item => item.id), ['coverage']);
});

test('exports retain publication stream and Bangladesh context without dropping source evidence', () => {
  const item = event({ category: 'News', stream: 'news', geography: ['Bangladesh'], bangladeshScope: 'coverage' });
  const csv = makeCSV([item]);
  assert.match(csv, /"Stream","Geography","Bangladesh scope"/);
  assert.match(csv, /"news","Bangladesh","coverage"\r\n$/);
  const brief = makeBrief(item);
  assert.match(brief, /Publication stream: Newsletter \/ news/);
  assert.match(brief, /Coverage \/ publisher region: Bangladesh/);
  assert.match(brief, /Bangladesh scope: Bangladesh coverage/);
  assert.match(brief, /does not establish a Bangladesh incident or victim location/);
  assert.match(brief, /https:\/\/www.php.net\/releases\//);
});

test('technical context is optional, bounded and keeps source context separate from review guidance', () => {
  const raw = event({ technicalDetails: {
    affectedSystems: [' Runtime 22 ', 'Runtime 22', null, '<img onerror=alert(1)>'],
    attackVector: 'not an array', prerequisites: ['x'.repeat(2000)],
    detection: Array.from({ length: 20 }, (_, index) => `Review ${index}`),
    mitigation: ['Apply the security release.'], limitations: [],
    reviewedAt: '2026-10-23', arbitrary: 'Ignored',
  } });
  const details = normalizeData(envelope([raw])).events[0].technicalDetails;
  assert.deepEqual(details.affectedSystems, ['Runtime 22', '<img onerror=alert(1)>']);
  assert.deepEqual(details.attackVector, []);
  assert.equal(details.prerequisites[0].length, 1200);
  assert.equal(details.detection.length, 12);
  assert.equal(details.reviewedAt, '2026-10-23');
  assert.equal(details.arbitrary, undefined);
  assert.equal(escapeHTML(details.affectedSystems[1]), '&lt;img onerror=alert(1)&gt;');
  for (const invalid of [undefined, null, [], 'data', {}, { reviewedAt: '2026-10-23' }]) {
    assert.equal(normalizeData(envelope([event({ technicalDetails: invalid })])).events[0].technicalDetails, null);
  }
  assert.equal(normalizeData(envelope([event({ technicalDetails: { detection: ['Review'], reviewedAt: '2026-02-31' } })])).events[0].technicalDetails.reviewedAt, null);
});

test('official CVE links require complete identifiers and never turn truncation into a different CVE', () => {
  assert.equal(cveURL(' CVE-2026-111497 '), 'https://www.cve.org/CVERecord?id=CVE-2026-111497');
  for (const invalid of ['CVE-2026-123', 'cve-2026-12345', 'CVE-2026-12345/other', 'CVE-2026-12345?redirect=evil',
    'CVE-2026-12345"><svg>', 'CVE-2026-' + '1'.repeat(100), 'javascript:alert(1)', null, 123]) {
    assert.equal(cveURL(invalid), '', String(invalid));
  }
  const result = normalizeData(envelope([event({ cves: ['CVE-2026-111497', 'CVE-2026-111497', 'CVE-2026-' + '1'.repeat(100), 'bad'] })]));
  assert.deepEqual(result.events[0].cves, ['CVE-2026-111497']);
});

test('related records prefer shared CVEs, explain exact organization matches, and exclude unrelated publisher stories', () => {
  const selected = event({ id: 'selected', cves: ['CVE-2026-10000', 'CVE-2026-10001'] });
  const records = [selected,
    event({ id: 'same-org', cves: ['CVE-2026-20000'], publishedAt: '2026-10-23T09:00:00Z' }),
    event({ id: 'one-cve', organization: 'Security team', cves: ['CVE-2026-10000'], publishedAt: '2026-10-23T10:00:00Z' }),
    event({ id: 'two-cves', organization: 'Different vendor', cves: ['CVE-2026-10001', 'CVE-2026-10000'] }),
    event({ id: 'future', publishedAt: '2026-10-24T00:00:00Z' }),
    event({ id: 'publisher-only', stream: 'news', category: 'News', cves: [] }),
    event({ id: 'same-source-only', organization: 'Unrelated vendor', cves: [] }),
  ];
  const result = relatedEvents(selected, records, { now: NOW });
  assert.deepEqual(result.map(item => item.event.id), ['two-cves', 'one-cve', 'same-org']);
  assert.equal(result[0].reason, 'Shared CVEs: CVE-2026-10000, CVE-2026-10001');
  assert.match(result[2].reason, /Same organization \/ product: PHP/);
  assert.deepEqual(relatedEvents(selected, [...records].reverse(), { now: NOW }), result);
  assert.equal(relatedEvents(selected, records, { now: NOW, limit: 1 }).length, 1);
  assert.equal(relatedEvents(selected, records, { now: NOW, limit: 0 }).length, 0);
  assert.deepEqual(relatedEvents(event({ organization: 'Unspecified', cves: [] }), [event({ id: 'generic', organization: 'Unspecified', cves: [] })], { now: NOW }), []);
  const news = event({ stream: 'news', category: 'News', cves: [] });
  assert.deepEqual(relatedEvents(news, [event({ id: 'another-story', stream: 'news', category: 'News', cves: [] })], { now: NOW }), []);
});

test('brief includes technical findings, analyst triage, official lookups and actual channel freshness', () => {
  const item = event({ technicalDetails: {
    affectedSystems: ['Runtime 22'], attackVector: [], prerequisites: ['Untrusted input reaches the decoder.'],
    detection: ['Review decoder crashes.'], mitigation: ['Update runtime.'], limitations: ['No deployment inventory available.'], reviewedAt: '2026-10-23',
  } });
  const brief = makeBrief(item, { name: 'PHP channel', kind: 'primary', status: 'error', lastSuccessAt: '2026-10-22T06:00:00Z', lastAttemptAt: '2026-10-23T06:00:00Z' });
  assert.match(brief, /AFFECTED SYSTEMS \/ VERSIONS — SOURCE CONTEXT\n• Runtime 22/);
  assert.match(brief, /DETECTION \/ TRIAGE — ANALYST REVIEW CHECKLIST\n• Review decoder crashes/);
  assert.match(brief, /KNOWN LIMITATIONS\n• No deployment inventory/);
  assert.match(brief, /Technical context reviewed: 2026-10-23/);
  assert.match(brief, /Last successful feed fetch: 2026-10-22T06:00:00Z/);
  assert.match(brief, /Last feed check attempt: 2026-10-23T06:00:00Z/);
  assert.match(brief, /Last collection status: error/);
  assert.match(brief, /https:\/\/www.cve.org\/CVERecord\?id=CVE-2026-10000/);
  const curated = makeBrief(item, { name: 'Verified reports', kind: 'curated' });
  assert.match(curated, /feed checks do not re-verify/);
  assert.doesNotMatch(curated, /Last successful feed fetch/);
});
