import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeData, filterEvents, isNewsboardEvent, matchesNewsTopic, safeImageURL, escapeHTML } from '../dist/core.js';

const now = Date.parse('2026-10-30T12:00:00Z');
const record = (id, sourceType, extras={}) => ({
  id, title: 'Organizations investigate a cyberattack and data breach', organization: 'A publisher',
  summary: 'Publisher reporting about a ransomware attack.', description: 'Details supplied by the source.',
  category: 'News', stream: 'news', publishedAt: '2026-10-29T10:00:00Z', updatedAt: '2026-10-29T10:00:00Z',
  sourceType, sourceId: id, severity: 'unknown', status: 'monitoring', sources: [], ...extras,
});
const envelope = (events, sources=[]) => ({schemaVersion:1,generatedAt:'2026-10-30T10:00:00Z',events,sources});

test('Newsboard combines reporting and official advisories without mixing in unrelated records',()=>{
  const items = [record('bbc','mainstream'),record('specialist','security'),record('vendor-research','vendor'),
    record('nginx','vendor',{category:'Advisory',stream:'intelligence'}),
    record('national-cert','government',{category:'Vulnerability',stream:'intelligence'}),
    record('reviewed','',{category:'Incident',stream:'intelligence'})];
  assert.deepEqual(filterEvents(items,{view:'newsboard',now}).map(item=>item.id),['bbc','national-cert','nginx','specialist','vendor-research']);
  assert.deepEqual(filterEvents(items,{view:'newsboard',newsScope:'mainstream',now}).map(item=>item.id),['bbc']);
  assert.deepEqual(filterEvents(items,{view:'newsboard',newsScope:'security',now}).map(item=>item.id),['specialist','vendor-research']);
  assert.deepEqual(filterEvents(items,{view:'newsboard',newsScope:'advisories',now}).map(item=>item.id),['national-cert','nginx']);
  assert.ok(!isNewsboardEvent(items[5]));
  assert.deepEqual(filterEvents(items,{view:'feed',now}).map(item=>item.id),['national-cert','nginx','reviewed']);
});

test('Newsboard topic, publisher, date, and text controls compose',()=>{
  const items=[record('bbc','mainstream',{title:'Exchange hacked',summary:'A technology report.',matchedKeywords:['hack']}),
    record('post','mainstream',{title:'Phishing campaign disclosed',summary:'Security coverage.'}),
    record('old','security',{publishedAt:'2026-08-01',title:'Exchange hacked'})];
  assert.deepEqual(filterEvents(items,{view:'newsboard',newsScope:'mainstream',newsTopic:'hack',source:'bbc',period:'7d',query:'exchange',now}).map(item=>item.id),['bbc']);
  assert.equal(filterEvents(items,{view:'newsboard',newsTopic:'malware',now}).length,0);
  assert.equal(matchesNewsTopic({title:'Manchester wins a game'},'hack'),false);
  assert.equal(matchesNewsTopic({title:'Zero day flaw disclosed'},'zero-day'),true);
  assert.equal(matchesNewsTopic({title:'Distributed denial-of-service disruption'},'ddos'),true);
  assert.equal(matchesNewsTopic({title:'Nothing here'},'unsupported'),false);
});

test('Source registry enriches legacy event types without fabricating article content',()=>{
  const result=normalizeData(envelope([
    record('bbc',''),record('nginx','',{category:'Advisory',stream:'intelligence'}),record('specialist',''),
  ],[
    {id:'bbc',group:'newsboard',kind:'secondary'},
    {id:'nginx',group:'intelligence',sourceType:'vendor'},
    {id:'specialist',group:'news',kind:'secondary'},
  ]));
  assert.equal(result.sources[0].group,'newsboard');
  assert.equal(result.events[0].sourceType,'mainstream');
  assert.equal(result.events[1].sourceType,'vendor');
  assert.equal(result.events[2].sourceType,'security');
  assert.equal(result.events[0].article,null);
});

test('Reader rejects executable and local image sources, including alternate IP notation',()=>{
  for(const value of [
    'javascript:alert(1)','data:image/svg+xml,<svg/>','http://www.bbc.com/a.jpg',
    'https://localhost/a.jpg','https://printer.local/a.jpg','https://files.internal/a.jpg',
    'https://127.0.0.1/a.jpg','https://10.0.0.1/a.jpg','https://2130706433/a.jpg',
    'https://0x7f000001/a.jpg','https://[::1]/a.jpg','https://[::ffff:127.0.0.1]/a.jpg',
    'https://example.com:8000/a.jpg','https://user:pass@example.com/a.jpg','https://example.com/a.svg',
    'https://example.com/a.svgz','//example.com/a.jpg',
  ]) assert.equal(safeImageURL(value),'',value);
  assert.equal(safeImageURL('https://ichef.bbci.co.uk/news/240/image.jpg'),'https://ichef.bbci.co.uk/news/240/image.jpg');
});

test('Reader bounds text and images and keeps article markup escaped at rendering',()=>{
  const result=normalizeData(envelope([record('unsafe','mainstream',{
    matchedKeywords:['hack','hack',null], article:{status:'full',paragraphs:['<script>alert(1)</script>','Text body'],
      images:[{url:'javascript:alert(1)'},{url:'https://ichef.bbci.co.uk/a.jpg',caption:'<img onerror=alert(1)>',credit:'Publisher'}],
      origin:'publisher',fetchedAt:'not-a-date',note:'<script>not executed</script>'},
  })])).events[0];
  assert.deepEqual(result.matchedKeywords,['hack']);
  assert.equal(result.article.images.length,1);
  assert.equal(result.article.fetchedAt,null);
  assert.equal(result.article.status,'full');
  assert.equal(escapeHTML(result.article.paragraphs[0]),'&lt;script&gt;alert(1)&lt;/script&gt;');
  assert.equal(escapeHTML(result.article.images[0].caption),'&lt;img onerror=alert(1)&gt;');
  const long=normalizeData(envelope([record('long','vendor',{article:{status:'full',paragraphs:Array.from({length:150},(_,i)=>`${i} ${'x'.repeat(5000)}`),images:[]}})])).events[0].article;
  assert.ok(long.paragraphs.length<=120);
  assert.ok(long.paragraphs.every(paragraph=>paragraph.length<=4000));
  assert.ok(long.paragraphs.join('').length<=100000);
  assert.equal(long.status,'excerpt','A clipped full article must not be advertised as complete.');
  const empty=normalizeData(envelope([record('empty','vendor',{article:{status:'full',paragraphs:[],images:[]}})])).events[0].article;
  assert.equal(empty.status,'unavailable');
});
