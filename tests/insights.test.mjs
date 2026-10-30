import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeData } from '../dist/core.js';
import { normalizeSourceChecks, sourceQualityRows, filterQualityRows, qualitySummary, makeQualityCSV, calendarDate, historyItems, monthCalendar, shiftMonth, makeHistoryCSV } from '../dist/insights-core.js';

const now=Date.parse('2026-10-31T10:00:00Z');
const source=(id,overrides={})=>({id,name:id,kind:'primary',group:'intelligence',status:'ok',lastAttemptAt:'2026-10-31T09:30:00Z',lastSuccessAt:'2026-10-31T09:30:00Z',...overrides});
const event=(id,overrides={})=>({id,sourceId:'vendor',title:'Security update',summary:'A vendor security advisory.',category:'Advisory',severity:'unknown',publishedAt:'2026-10-31T09:00:00Z',sources:[{name:'Vendor',url:'https://example.com/security'}],cves:[],timeline:[],...overrides});

test('source metrics distinguish failing, overdue, unobserved, zero-item success and manual records',()=>{
  const data={sources:[source('zero'),source('old',{lastAttemptAt:'2026-10-31T06:00:00Z'}),source('failed',{status:'error'}),source('unknown',{lastAttemptAt:null}),source('curated',{kind:'curated',status:'snapshot',lastAttemptAt:null})],events:[]};
  const rows=sourceQualityRows(data,{now});
  assert.deepEqual(rows.map(row=>row.status),['ok','stale','error','unknown','manual']);
  assert.equal(rows[0].recordCount,0);assert.equal(rows[0].successRate,100);assert.equal(rows[0].checks.length,1);
  assert.equal(rows[4].successRate,null);assert.equal(qualitySummary(rows).automatic,4);
  assert.deepEqual(filterQualityRows(rows,{status:'attention'}).map(row=>row.id),['failed','old','unknown']);
});

test('history of checks uses recorded samples without estimating missing runs',()=>{
  const collectionHistory=[{at:'2026-10-20T10:00:00Z',status:'error',recordCount:4},{at:'2026-10-31T09:30:00Z',status:'ok',recordCount:0}];
  const row=sourceQualityRows({sources:[source('x',{collectionHistory})],events:[]},{now})[0];
  assert.equal(row.checks.length,2);assert.equal(row.successRate,50);assert.equal(row.successes,1);
  assert.equal(normalizeSourceChecks([...collectionHistory,collectionHistory[0],{at:'invalid',status:'ok',recordCount:2}]).length,2);
});

test('reader coverage counts full, excerpt, restricted and context without inventing content',()=>{
  const data={sources:[source('vendor')],events:['full','excerpt','restricted',null].map((status,index)=>event(String(index),{article:status?{status}:null}))};
  const row=sourceQualityRows(data,{now})[0];
  assert.deepEqual(row.coverage,{full:1,excerpt:1,restricted:1,unavailable:1});
  assert.equal(row.recordCount,4);assert.equal(qualitySummary([row]).full,1);
});

test('calendar dates convert timezone-qualified instants but preserve date-only values',()=>{
  assert.equal(calendarDate('2026-10-30T20:00:00Z'),'2026-10-31');
  assert.equal(calendarDate('2026-10-30'),'2026-10-30');
  assert.equal(calendarDate('2026-02-31'),'');assert.equal(calendarDate('invalid'),'');
  const cells=monthCalendar('2024-02');assert.equal(cells.filter(cell=>cell.inMonth).length,29);
  assert.equal(cells[0].day,'2024-01-29');assert.equal(cells.length%7,0);
  assert.equal(shiftMonth('2026-12',1),'2027-01');assert.equal(shiftMonth('2026-01',-1),'2025-12');
});

test('incident history never treats a feed publication date as an attack milestone',()=>{
  const data={sources:[source('curated',{kind:'curated'}),source('vendor')],events:[event('reviewed',{sourceId:'curated',category:'Incident',severity:'high',publishedAt:'2026-10-22',timeline:[{date:'2026-10-19',title:'Access detected',description:'Source-documented detection date.'}]}),event('feed',{severity:'critical',timeline:[{date:'2026-10-21',title:'Advisory published',description:'Publication date.'}]})]};
  const milestones=historyItems(data);assert.equal(milestones.length,1);assert.equal(milestones[0].day,'2026-10-19');
  const publications=historyItems(data,{basis:'publications'});assert.equal(publications.length,2);assert.equal(publications.find(item=>item.event.id==='reviewed').day,'2026-10-22');
});

test('history excludes research and irrelevant reporting, major scope does not inflate unknown news',()=>{
  const data={sources:[source('vendor'),source('news',{kind:'secondary'})],events:[event('research',{research:true,category:'News',title:'New security testing method'}),event('bad',{sourceId:'news',category:'News',title:'GM cracks the petty cash box for multistate driver tracking settlement',summary:'Consumer privacy settlement for driving data.'}),event('news',{sourceId:'news',category:'News',title:'Company confirms ransomware attack',summary:'A cybersecurity incident is under investigation.'}),event('exploited',{exploited:true})]};
  assert.deepEqual(historyItems(data,{basis:'publications',scope:'all'}).map(item=>item.event.id).sort(),['exploited','news']);
  assert.deepEqual(historyItems(data,{basis:'publications',scope:'major'}).map(item=>item.event.id),['exploited']);
  assert.equal(historyItems(data,{basis:'publications',scope:'all',query:'ransomware'})[0].event.id,'news');
});

test('CSV exports keep the date basis and neutralize spreadsheet formula cells',()=>{
  const data={sources:[source('vendor',{name:'=HYPERLINK("bad")'})],events:[event('e',{category:'Incident',title:'=1+1'})]};
  assert.match(makeQualityCSV(sourceQualityRows(data,{now})),/"'=HYPERLINK/);
  const csv=makeHistoryCSV(historyItems(data,{basis:'publications'}));
  assert.match(csv,/"publications"/);assert.match(csv,/"'=1\+1"/);
});

test('new telemetry remains optional for old snapshots and unsafe full flags are downgraded',()=>{
  const data=normalizeData({schemaVersion:1,generatedAt:'2026-10-31T10:00:00Z',sources:[source('vendor')],events:[event('e',{article:{status:'full',origin:'feed',paragraphs:['Partial text'],truncated:true,availabilityReason:'publisher-partial'}})]});
  assert.deepEqual(data.sources[0].collectionHistory,[]);
  assert.equal(data.events[0].article.status,'excerpt');assert.equal(data.events[0].article.truncated,true);
});

test('browser rejects collection samples that follow the recorded source attempt',()=>{
  const snapshot={schemaVersion:1,generatedAt:'2026-10-31T12:00:00Z',events:[],sources:[source('vendor',{lastAttemptAt:'2026-10-31T10:00:00Z',collectionHistory:[{at:'2026-10-31T10:00:00Z',status:'ok',recordCount:0},{at:'2026-10-31T10:01:00Z',status:'ok',recordCount:0}]})]};
  assert.equal(normalizeData(snapshot).sources[0].collectionHistory.length,1);
});
