/** Pure, dependency-free data handling shared by the console and its tests. */
export const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'unknown']);

const CATEGORIES = new Map([
  ['incident', 'Incident'], ['vulnerability', 'Vulnerability'],
  ['advisory', 'Advisory'], ['patch', 'Patch'], ['news', 'News'],
]);
const STATUSES = new Set(['investigating', 'active', 'mitigated', 'resolved', 'monitoring']);
const BANGLADESH_SCOPES = new Set(['national-advisory', 'local-activity', 'coverage']);
const SOURCE_GROUPS = new Set(['news', 'intelligence', 'bangladesh']);
const MAX_EVENTS = 2000;
const TECHNICAL_FIELDS = ['affectedSystems', 'attackVector', 'prerequisites', 'detection', 'mitigation', 'limitations'];
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;

function text(value, limit = 4000) {
  return typeof value === 'string' ? value.trim().slice(0, limit) : '';
}

function strings(value, limit = 60, width = 1200) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.slice(0, limit).map(item => text(item, width)).filter(Boolean))];
}

function isoDate(value) {
  const candidate = text(value, 80);
  if (!/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2}))?$/.test(candidate)) return null;
  const [year, month, day] = candidate.slice(0, 10).split('-').map(Number);
  const maxDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (month < 1 || month > 12 || day < 1 || day > maxDay) return null;
  const milliseconds = Date.parse(candidate);
  return Number.isFinite(milliseconds) ? (candidate.length === 10 ? candidate : new Date(milliseconds).toISOString()) : null;
}

function isoTimestamp(value) {
  const date = isoDate(value);
  return date && date.includes('T') ? date : null;
}

/** News is a separate publication stream, including legacy News-category entries. */
export function isNewsEvent(event) {
  return text(event?.stream, 30).toLowerCase() === 'news' || text(event?.category, 30).toLowerCase() === 'news';
}

/** Match explicit regional attribution; a global bulletin does not establish local activity. */
export function isBangladeshEvent(event) {
  return BANGLADESH_SCOPES.has(text(event?.bangladeshScope, 40).toLowerCase()) ||
    (Array.isArray(event?.geography) && event.geography.some(country => /^(?:bangladesh|bd|বাংলাদেশ)$/iu.test(text(country, 160))));
}

/** Escape only at the HTML rendering boundary; normalized feed text stays plain. */
export function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

/** Source links must be absolute HTTP(S) URLs, without embedded credentials. */
export function safeURL(value) {
  if (typeof value !== 'string' || value.length > 4096) return '';
  const candidate = value.trim();
  if (!/^https?:\/\//i.test(candidate) || /[\u0000-\u001f\u007f\\]/.test(candidate)) return '';
  try {
    const parsed = new URL(candidate);
    if (!['https:', 'http:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) return '';
    return parsed.href;
  } catch {
    return '';
  }
}

/** Build an official record link only from a complete, valid CVE identifier. */
export function cveURL(value) {
  if (typeof value !== 'string' || value.trim().length > 80) return '';
  const identifier = value.trim();
  return CVE_PATTERN.test(identifier) ? `https://www.cve.org/CVERecord?id=${identifier}` : '';
}

function cveIdentifiers(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.slice(0, 500).filter(cve => cveURL(cve)).map(cve => cve.trim()))];
}

function normalizeTechnicalDetails(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const details = Object.fromEntries(TECHNICAL_FIELDS.map(field => [field, strings(value[field], 12, 1200)]));
  if (!TECHNICAL_FIELDS.some(field => details[field].length)) return null;
  return { ...details, reviewedAt: isoDate(value.reviewedAt) };
}

function normalizeEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const id = text(raw.id, 180);
  const title = text(raw.title, 320);
  const publishedAt = isoDate(raw.publishedAt);
  if (!id || !title || !publishedAt) return null;
  const description = text(raw.description, 18000) || text(raw.summary, 18000);
  const summary = text(raw.summary, 1200) || description.slice(0, 360);
  const severity = text(raw.severity, 20).toLowerCase();
  const status = text(raw.status, 30).toLowerCase();
  const bangladeshScope = text(raw.bangladeshScope, 40).toLowerCase();
  const sources = (Array.isArray(raw.sources) ? raw.sources : []).slice(0, 30)
    .filter(source => source && typeof source === 'object')
    .map(source => ({
      name: text(source.name, 160) || 'Source',
      url: safeURL(source.url),
      publishedAt: isoDate(source.publishedAt),
      kind: source.kind === 'secondary' ? 'secondary' : 'primary',
    })).filter(source => source.url);
  const timeline = (Array.isArray(raw.timeline) ? raw.timeline : []).slice(0, 100)
    .filter(entry => entry && typeof entry === 'object')
    .map(entry => ({
      date: isoDate(entry.date),
      title: text(entry.title, 240),
      description: text(entry.description, 4000),
    })).filter(entry => entry.date && (entry.title || entry.description))
    .sort((a, b) => Date.parse(a.date) - Date.parse(b.date));
  return {
    id, title, organization: text(raw.organization, 180) || 'Unspecified',
    summary, description,
    category: CATEGORIES.get(text(raw.category, 30).toLowerCase()) || 'Advisory',
    stream: isNewsEvent(raw) ? 'news' : 'intelligence',
    bangladeshScope: BANGLADESH_SCOPES.has(bangladeshScope) ? bangladeshScope : null,
    severity: SEVERITIES.includes(severity) ? severity : 'unknown',
    status: STATUSES.has(status) ? status : 'monitoring',
    publishedAt, updatedAt: isoDate(raw.updatedAt) || publishedAt,
    geography: strings(raw.geography, 50, 160), sectors: strings(raw.sectors, 50, 160),
    cves: cveIdentifiers(raw.cves), tags: strings(raw.tags, 60, 160),
    impact: strings(raw.impact, 40, 4000), recommendations: strings(raw.recommendations, 40, 4000),
    timeline, sources,
    confidence: raw.confidence === 'confirmed' ? 'confirmed' : 'reported',
    severityBasis: text(raw.severityBasis, 4000) || 'Severity has not been independently assessed.',
    evidenceNote: text(raw.evidenceNote, 5000),
    technicalDetails: normalizeTechnicalDetails(raw.technicalDetails),
    sourceId: text(raw.sourceId, 180) || 'unassigned',
    exploited: raw.exploited === true,
  };
}

/** Explain every related record; sharing a publisher alone is not a relationship. */
export function relatedEvents(event, events, { limit = 4, now = Date.now() } = {}) {
  if (!event || !Array.isArray(events)) return [];
  const referenceTime = now instanceof Date ? now.getTime() : Number(now);
  const cutoff = Number.isFinite(referenceTime) ? referenceTime : Date.now();
  const cves = new Set(cveIdentifiers(event.cves));
  const organization = text(event.organization, 180).toLocaleLowerCase();
  const specificOrganization = organization && !/^(?:unspecified|unknown|multiple(?: organizations| vendors)?|various|global|cross-sector|cisa|bsc e-gov cirt|bgd e-gov cirt)$/i.test(organization);
  const seen = new Set([event.id]);
  const related = [];
  for (const candidate of events) {
    if (!candidate || seen.has(candidate.id)) continue;
    seen.add(candidate.id);
    const published = Date.parse(candidate.publishedAt);
    if (!Number.isFinite(published) || published > cutoff) continue;
    const sharedCves = cveIdentifiers(candidate.cves).filter(cve => cves.has(cve)).sort();
    // News organization fields identify publishers, not necessarily affected entities.
    const sameOrganization = !isNewsEvent(event) && !isNewsEvent(candidate) && specificOrganization &&
      organization === text(candidate.organization, 180).toLocaleLowerCase();
    if (!sharedCves.length && !sameOrganization) continue;
    related.push({ event: candidate, sharedCves, reason: sharedCves.length
      ? `Shared ${sharedCves.length === 1 ? 'CVE' : 'CVEs'}: ${sharedCves.slice(0, 3).join(', ')}${sharedCves.length > 3 ? ` +${sharedCves.length - 3}` : ''}`
      : `Same organization / product: ${event.organization}` });
  }
  return related.sort((a, b) => b.sharedCves.length - a.sharedCves.length ||
    Date.parse(b.event.publishedAt) - Date.parse(a.event.publishedAt) ||
    String(a.event.id).localeCompare(String(b.event.id)))
    .slice(0, Math.min(8, Math.max(0, Number.isFinite(Number(limit)) ? Number(limit) : 4)));
}

/** Validate a snapshot envelope and limit untrusted fields before rendering. */
export function normalizeData(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || raw.schemaVersion !== 1 || !Array.isArray(raw.events) || !Array.isArray(raw.sources)) {
    throw new TypeError('Unsupported intelligence snapshot. Expected schemaVersion 1, events, and sources.');
  }
  const generatedAt = isoDate(raw.generatedAt);
  if (!generatedAt) throw new TypeError('The intelligence snapshot has no valid collection timestamp.');
  const eventIds = new Set();
  const events = [];
  for (const item of raw.events.slice(0, MAX_EVENTS)) {
    const event = normalizeEvent(item);
    if (!event || eventIds.has(event.id)) continue;
    eventIds.add(event.id);
    events.push(event);
  }
  const sourceIds = new Set();
  const sources = [];
  for (const item of raw.sources.slice(0, 100)) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const id = text(item.id, 180);
    if (!id || sourceIds.has(id)) continue;
    sourceIds.add(id);
    sources.push({
      id, name: text(item.name, 180) || id,
      url: safeURL(item.url) || null,
      kind: ['primary', 'secondary', 'curated'].includes(item.kind) ? item.kind : 'primary',
      group: SOURCE_GROUPS.has(item.group) ? item.group : 'intelligence',
      description: text(item.description, 2000),
      status: ['ok', 'error', 'snapshot'].includes(item.status) ? item.status : 'snapshot',
      lastSuccessAt: isoTimestamp(item.lastSuccessAt),
      lastAttemptAt: isoTimestamp(item.lastAttemptAt),
      itemCount: events.filter(event => event.sourceId === id).length,
      error: text(item.error, 2000) || null,
    });
  }
  // Loading a snapshot is not a feed check. Legacy timestamps may only be
  // recovered from recorded attempts, never from the browser's current time.
  const attempts = sources.filter(source => source.kind !== 'curated' && source.lastAttemptAt)
    .map(source => source.lastAttemptAt).sort((a, b) => Date.parse(b) - Date.parse(a));
  const databaseUpdatedAt = raw.databaseUpdatedAt === undefined ? isoTimestamp(generatedAt) : isoTimestamp(raw.databaseUpdatedAt);
  const lastCheckedAt = raw.lastCheckedAt === undefined ? (attempts[0] || null) : isoTimestamp(raw.lastCheckedAt);
  return { schemaVersion: 1, generatedAt, databaseUpdatedAt, lastCheckedAt, sources, events };
}

/** Search, combine filters, and sort without mutating the supplied event array. */
export function filterEvents(events, {
  query = '', severity = 'all', category = 'all', period = 'all', source = 'all',
  view = 'feed', regionScope = 'all', savedIds = [], sort = 'newest', now = Date.now(),
} = {}) {
  const tokens = String(query ?? '').trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  const saved = savedIds instanceof Set ? savedIds : new Set(Array.isArray(savedIds) ? savedIds : []);
  const referenceTime = now instanceof Date ? now.getTime() : Number(now);
  const currentTime = Number.isFinite(referenceTime) ? referenceTime : Date.now();
  const duration = { '24h': 86400000, '7d': 604800000, '30d': 2592000000 }[period];
  const sourceQuery = String(source).toLocaleLowerCase();
  const result = (Array.isArray(events) ? events : []).filter(event => {
    const timestamp = Date.parse(event.publishedAt);
    if (!Number.isFinite(timestamp) || timestamp > currentTime) return false;
    if (duration && timestamp < currentTime - duration) return false;
    if (severity !== 'all' && event.severity !== severity) return false;
    if (category !== 'all' && event.category !== category) return false;
    if (view === 'feed' && isNewsEvent(event)) return false;
    if (view === 'newsletters' && !isNewsEvent(event)) return false;
    if (view === 'bangladesh' && !isBangladeshEvent(event)) return false;
    if (regionScope !== 'all' && event.bangladeshScope !== regionScope) return false;
    if (view === 'watchlist' && !saved.has(event.id)) return false;
    if (source !== 'all' && String(event.sourceId).toLocaleLowerCase() !== sourceQuery && !(event.sources || []).some(item => String(item.name).toLocaleLowerCase() === sourceQuery)) return false;
    if (tokens.length) {
      const haystack = [event.title, event.organization, event.summary, event.description,
        ...(event.cves || []), ...(event.tags || []), ...(event.geography || []), ...(event.sectors || [])]
        .join(' ').toLocaleLowerCase();
      if (!tokens.every(token => haystack.includes(token))) return false;
    }
    return true;
  });
  const newest = (a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt) || String(a.id).localeCompare(String(b.id));
  if (sort === 'severity') {
    return result.sort((a, b) => {
      const left = SEVERITIES.indexOf(a.severity), right = SEVERITIES.indexOf(b.severity);
      return (left < 0 ? 4 : left) - (right < 0 ? 4 : right) || newest(a, b);
    });
  }
  if (sort === 'updated') return result.sort((a, b) => Date.parse(b.updatedAt || b.publishedAt) - Date.parse(a.updatedAt || a.publishedAt) || newest(a, b));
  return result.sort(newest);
}

function csvCell(value) {
  let result = String(value ?? '');
  // Spreadsheet software can interpret formulas even after whitespace/BOMs.
  if (/^[\s\u0000-\u001f]*[=+\-@]/u.test(result) || /^[\t\r\n]/.test(result)) result = `'${result}`;
  return `"${result.replace(/"/g, '""')}"`;
}

/** An Excel-friendly UTF-8 CSV with every field quoted and formula-safe. */
export function makeCSV(events) {
  const rows = [[
    'ID', 'Published at', 'Updated at', 'Organization', 'Title', 'Category', 'Severity',
    'Severity basis', 'Status', 'Confidence', 'Exploitation reported', 'CVEs', 'Summary',
    'Impact', 'Recommendations', 'Sources', 'Stream', 'Geography', 'Bangladesh scope',
  ]];
  for (const event of events || []) {
    rows.push([
      event.id, event.publishedAt, event.updatedAt, event.organization, event.title, event.category,
      event.severity, event.severityBasis, event.status, event.confidence, event.exploited ? 'Yes' : 'Not established',
      (event.cves || []).join('; '), event.summary,
      (event.impact || []).join('\n'), (event.recommendations || []).join('\n'),
      (event.sources || []).map(source => safeURL(source.url)).filter(Boolean).join('\n'),
      isNewsEvent(event) ? 'news' : 'intelligence', (event.geography || []).join('; '), event.bangladeshScope || '',
    ]);
  }
  return '\uFEFF' + rows.map(row => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

/** Plain-text, source-attributed summary for copying into an analyst briefing. */
export function makeBrief(event, channel = null) {
  const severity = event.severity === 'unknown' ? 'Not assessed' : String(event.severity || 'unknown').toUpperCase();
  const lines = [
    event.title,
    `${event.organization} · ${event.category}`,
    `Published: ${event.publishedAt}`,
    `Record updated: ${event.updatedAt || event.publishedAt}`,
    `Severity: ${severity}`,
    `Severity basis: ${event.severityBasis || 'Not independently assessed.'}`,
    `Status: ${event.status} · Evidence: ${event.confidence}`,
    `Exploitation: ${event.exploited ? 'Reported in source material' : 'Not established by this record'}`,
  ];
  if (isNewsEvent(event)) lines.push('Publication stream: Newsletter / news');
  if (event.geography?.length) lines.push(`${event.bangladeshScope === 'coverage' ? 'Coverage / publisher region' : 'Geography'}: ${event.geography.join(', ')}`);
  if (BANGLADESH_SCOPES.has(event.bangladeshScope)) {
    const scope = { 'national-advisory': 'National advisory', 'local-activity': 'Local cyber activity', coverage: 'Bangladesh coverage' }[event.bangladeshScope];
    lines.push(`Bangladesh scope: ${scope}`);
    if (event.bangladeshScope === 'coverage') lines.push('Bangladesh publisher coverage does not establish a Bangladesh incident or victim location.');
  }
  if (event.cves?.length) lines.push(`CVEs: ${event.cves.join(', ')}`);
  if (channel) {
    lines.push(`Source channel: ${channel.name || event.sourceId}`);
    if (channel.kind === 'curated') lines.push('Collection: Curated record; feed checks do not re-verify its contents.');
    else lines.push(`Last successful feed fetch: ${channel.lastSuccessAt || 'Not recorded'}`,
      `Last feed check attempt: ${channel.lastAttemptAt || 'Not recorded'}`,
      `Last collection status: ${channel.status || 'Not recorded'}`);
  }
  lines.push('', 'DESCRIPTION', event.description || event.summary || 'No description available.');
  if (event.impact?.length) lines.push('', 'IMPACT', ...event.impact.map(item => `• ${item}`));
  if (event.recommendations?.length) lines.push('', 'RECOMMENDATIONS', ...event.recommendations.map(item => `• ${item}`));
  const details = normalizeTechnicalDetails(event.technicalDetails);
  if (details) {
    if (details.reviewedAt) lines.push('', `Technical context reviewed: ${details.reviewedAt}`);
    const labels = { affectedSystems: 'AFFECTED SYSTEMS / VERSIONS — SOURCE CONTEXT', attackVector: 'ATTACK VECTOR — SOURCE CONTEXT',
      prerequisites: 'EXPOSURE CONDITIONS — SOURCE CONTEXT', detection: 'DETECTION / TRIAGE — ANALYST REVIEW CHECKLIST',
      mitigation: 'MITIGATION / RESPONSE — SOURCE CONTEXT', limitations: 'KNOWN LIMITATIONS' };
    for (const field of TECHNICAL_FIELDS) {
      if (details[field].length) lines.push('', labels[field], ...details[field].map(item => `• ${item}`));
    }
  }
  const cveLinks = cveIdentifiers(event.cves).map(cve => ({ cve, url: cveURL(cve) }));
  if (cveLinks.length) lines.push('', 'OFFICIAL CVE RECORDS', ...cveLinks.map(item => `${item.cve}: ${item.url}`));
  if (event.evidenceNote) lines.push('', 'EVIDENCE NOTE', event.evidenceNote);
  if (event.timeline?.length) lines.push('', 'TIMELINE', ...event.timeline.map(item => `${item.date} — ${item.title}${item.description ? `: ${item.description}` : ''}`));
  const sources = (event.sources || []).map(source => ({ ...source, url: safeURL(source.url) })).filter(source => source.url);
  if (sources.length) lines.push('', 'SOURCES', ...sources.map(source => `${source.name}: ${source.url}`));
  return lines.filter(line => line !== undefined && line !== null).join('\n');
}
