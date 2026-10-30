import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeData, filterEvents, isNewsboardEvent, newsRelevance } from '../dist/core.js';
import { normalizeNewsRelevance } from '../dist/news-relevance.js';

const now = Date.parse('2026-10-30T23:00:00Z');
const GM = 'GM cracks the petty cash box for multistate driver tracking settlement';
const record = (title, extras = {}) => ({
  id: 'example', title, category: 'News', stream: 'news',
  sourceType: 'security', sourceId: 'the-register',
  publishedAt: '2026-10-30T10:00:00Z', updatedAt: '2026-10-30T10:00:00Z',
  summary: '', description: '', ...extras,
});
const envelope = events => ({schemaVersion:1,generatedAt:'2026-10-30T12:00:00Z',events,sources:[]});

test('The reported GM false positive is excluded regardless of publisher type or stale tags', () => {
  for (const sourceType of ['mainstream', 'security', 'vendor', 'government']) {
    const event = record(GM, {
      sourceType, organization: 'Cybersecurity Research Daily',
      tags: ['Cybersecurity'], matchedKeywords: ['hack', 'vulnerability'],
      recommendations: ['Assess ransomware exposure.'], evidenceNote: 'Review cybersecurity implications.',
      description: 'The regulator said it compromised consumer privacy by sharing driving data with insurers.',
    });
    assert.equal(isNewsboardEvent(event), false, sourceType);
    assert.equal(filterEvents([event], {view:'newsboard',now}).length, 0);
    assert.equal(filterEvents([event], {view:'newsletters',now}).length, 1,
      'The broader publisher-updates view retains its existing behavior.');
  }
});

test('Privacy and general business headlines need an actual cybersecurity connection', () => {
  for (const title of [
    'French privacy watchdog fines FNAC for tracking app users without consent',
    'Google suffers its worst value crash in history amid AI bubble burst fears',
    'Anthropic files for an initial public offering',
    'OpenAI doubles ChatGPT Pro usage limits after backlash',
    'Samsung One UI update leaves some phones stuck in setup mode or with drained battery',
    'Apple warns of economic vulnerabilities in emerging markets',
    'Five kitchen hacks that make dinner easier',
    'Thief stole a physical wallet outside the stock exchange',
  ]) assert.equal(isNewsboardEvent(record(title)), false, title);
  for (const title of [
    'Company settles lawsuit over customer data breach',
    'Court sentences ransomware operator after hospital attacks',
    'Privacy watchdog fines company after hackers stole customer records',
  ]) assert.equal(isNewsboardEvent(record(title)), true, title);
});

test('Real security reporting remains eligible without requiring the word cyber', () => {
  for (const title of [
    'Claude Code extension poisoned with persistent SSH backdoor',
    'Telegram Android flaw lets attackers run code when users answer calls',
    'Cloud and AI credentials found exposed in public repositories',
    'New prompt injection techniques cover agent-planning attacks',
    'GitHub launches npm firewall to block malicious packages',
    'Passkeys are better than passwords but are not enough',
    'Threat modeling with four simple questions',
    'Why CTF competitions are important for defenders',
    'Attackers bypass LLM safety classifiers',
    'Crypto giant Binance hit by a multibillion-dollar hack',
    'SS7 and Diameter attacks expose mobile phone communications',
    'বাংলাদেশে সাইবার নিরাপত্তা সচেতনতা কর্মসূচি',
  ]) assert.equal(isNewsboardEvent(record(title)), true, title);
});

test('Fallback examines the publisher lead rather than incidental late body text or boilerplate', () => {
  const prefix = 'The company described its trading results and shareholder outlook. '.repeat(45);
  assert.equal(isNewsboardEvent(record('Company releases quarterly results', {
    article:{paragraphs:[prefix, 'A standard risk appendix mentions ransomware and phishing.']},
  })), false);
  assert.equal(isNewsboardEvent(record('Publisher announces changes', {
    description:'Read the original Cybersecurity Daily article for the complete report. CyberWatch displays its headline, publication date and source link.',
  })), false);
  assert.equal(isNewsboardEvent(record('Hospital service interruption under investigation', {
    article:{paragraphs:['The hospital confirmed a ransomware attack disrupted its systems.']},
  })), true);
});

test('Current collector decisions normalize strictly; invalid or obsolete metadata uses content fallback', () => {
  const accepted = {version:1,relevant:true,matchedKeywords:['custom security term'],reason:'Configured cybersecurity topic.'};
  const denied = {version:1,relevant:false,matchedKeywords:[],reason:'No direct cybersecurity topic in the headline or lead.'};
  assert.deepEqual(normalizeNewsRelevance(accepted), accepted);
  assert.equal(isNewsboardEvent(record('Custom publication', {newsRelevance:accepted})), true);
  assert.equal(isNewsboardEvent(record(GM, {newsRelevance:denied})), false);
  for (const metadata of [
    null, [], 'true', {version:1,relevant:'true',matchedKeywords:[],reason:'Not a boolean'},
    {...accepted,version:'1'}, {...accepted,version:true}, {...accepted,version:0}, {...accepted,version:999},
    {...accepted,matchedKeywords:'hack'}, {...accepted,reason:{text:'not plain text'}},
    {...accepted,matchedKeywords:Array(41).fill('hack')},
    {...accepted,matchedKeywords:['x'.repeat(101)]}, {...accepted,reason:'x'.repeat(501)},
  ]) {
    assert.equal(normalizeNewsRelevance(metadata), null);
    assert.equal(isNewsboardEvent(record(GM, {newsRelevance:metadata})), false);
    assert.equal(isNewsboardEvent(record('Phishing campaign disclosed', {newsRelevance:metadata})), true);
  }
  const normalized = normalizeData(envelope([record(GM,{newsRelevance:denied})])).events[0];
  assert.deepEqual(normalized.newsRelevance, denied);
});

test('Newsboard relevance does not exclude official advisory records or change incident filtering', () => {
  const items = [
    record(GM),
    record('Official vendor notice',{id:'vendor',stream:'intelligence',category:'Advisory',sourceType:'vendor'}),
    record('National security bulletin',{id:'cert',stream:'intelligence',category:'Vulnerability',sourceType:'government'}),
    record('Reviewed compromise',{id:'incident',stream:'intelligence',category:'Incident',sourceType:''}),
  ];
  assert.deepEqual(filterEvents(items,{view:'newsboard',now}).map(item=>item.id),['cert','vendor']);
  assert.deepEqual(filterEvents(items,{view:'feed',now}).map(item=>item.id),['cert','incident','vendor']);
  assert.equal(newsRelevance(record(GM)).relevant, false);
});
