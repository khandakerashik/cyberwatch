/** Article-level Newsboard eligibility shared with the collector's rule data. */
import RULES from './news-relevance-rules.js';

const signals = RULES.signals.map(rule => ({
  ...rule,
  expression: new RegExp(rule.pattern, 'i'),
  contextExpression: rule.context ? new RegExp(rule.context, 'i') : null,
  rejectExpression: rule.reject ? new RegExp(rule.reject, 'i') : null,
}));
const titleExclusions = RULES.strictTitleExclusions.map(pattern => new RegExp(pattern, 'i'));
const boilerplate = RULES.boilerplatePatterns.map(pattern => new RegExp(pattern, 'i'));

function plain(value, maximum) {
  return typeof value === 'string' ? value.replace(/\s+/g, ' ').trim().slice(0, maximum) : '';
}

function publisherText(value) {
  const lead = plain(value, RULES.maxLeadChars);
  return lead && !boilerplate.some(pattern => pattern.test(lead)) ? lead : '';
}

/** Invalid/obsolete metadata must not silently approve unrelated legacy news. */
export function normalizeNewsRelevance(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      value.version !== RULES.version || typeof value.relevant !== 'boolean' ||
      !Array.isArray(value.matchedKeywords) || value.matchedKeywords.length > 40 ||
      !value.matchedKeywords.every(item => typeof item === 'string' && item.trim() && item.length <= 100) ||
      typeof value.reason !== 'string' || !value.reason.trim() || value.reason.length > 500) return null;
  return {
    version: RULES.version,
    relevant: value.relevant,
    matchedKeywords: [...new Set(value.matchedKeywords.map(item => item.trim()))],
    reason: value.reason.trim(),
  };
}

/** A publisher name, cached keywords and analyst boilerplate are not evidence. */
export function publisherLead(event) {
  const paragraphs = Array.isArray(event?.article?.paragraphs)
    ? event.article.paragraphs.slice(0, 120).filter(value => typeof value === 'string').map(publisherText).filter(Boolean).join(' ')
    : '';
  for (const candidate of [paragraphs, event?.description, event?.summary]) {
    const lead = publisherText(candidate);
    if (lead) return lead;
  }
  return '';
}

function matchingSignals(value, context = value) {
  return signals.filter(rule => rule.expression.test(value) &&
    (!rule.contextExpression || rule.contextExpression.test(context)) &&
    (!rule.rejectExpression || !rule.rejectExpression.test(context)));
}

/** Fallback for snapshots collected before article-level relevance was added. */
export function evaluateNewsRelevance(titleValue, leadValue = '') {
  const title = plain(titleValue, RULES.maxTitleChars);
  const lead = publisherText(leadValue);
  const combined = `${title} ${lead}`.trim();
  const titleSignals = matchingSignals(title);
  const matches = matchingSignals(combined);
  if (titleExclusions.some(pattern => pattern.test(title)) && !titleSignals.some(rule => rule.incident)) {
    return {
      version:RULES.version, relevant:false, matchedKeywords:[],
      reason:'General business, consumer privacy or technology coverage without a cybersecurity incident in the title.',
    };
  }
  const labels = [...new Set(matches.map(rule => rule.label))].slice(0, 40);
  return {
    version:RULES.version, relevant:labels.length > 0, matchedKeywords:labels,
    reason:labels.length
      ? 'Clear cybersecurity subject in the article title or publisher lead.'
      : 'No clear cybersecurity subject in the article title or publisher lead.',
  };
}

export function newsRelevance(event) {
  const current = normalizeNewsRelevance(event?.newsRelevance);
  return current || evaluateNewsRelevance(event?.title, publisherLead(event));
}
