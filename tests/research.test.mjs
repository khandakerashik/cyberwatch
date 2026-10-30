import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeData,filterEvents,isNewsboardEvent,makeCSV,makeBrief} from '../dist/core.js';
import {normalizeLearning,normalizeResearchWatch,normalizeResearchPreferences,filterResearchItems,filterTechniques,LEARNING_PATHS,TECHNIQUE_LIBRARY} from '../dist/research-core.js';

const now=Date.parse('2026-10-30T16:00:00Z');
const learning={kind:'research',domains:['web','api'],perspectives:['offensive','defensive'],project:'Primary researcher',releaseStatus:'unknown',dateBasis:'source-published'};
const event=(id,extras={})=>({id,title:'New access-control testing research',organization:'Research source',summary:'Study an authorization boundary and validate server-side access controls.',description:'Primary publication context.',publishedAt:'2026-10-29T10:00:00Z',updatedAt:'2026-10-29T10:00:00Z',stream:'news',category:'News',severity:'unknown',sourceId:'research-source',sources:[{name:'Research source',url:'https://example.com/research',kind:'primary'}],cves:[],tags:[],impact:[],recommendations:[],geography:[],learning,...extras});
const snapshot=events=>({schemaVersion:1,generatedAt:'2026-10-30T15:00:00Z',events,sources:[{id:'research-source',name:'Original research',group:'research',kind:'primary',status:'ok',learning}]});

test('research is isolated from incident/news views but remains available in watchlists',()=>{
  const data=normalizeData(snapshot([event('research'),event('legacy',{learning:undefined}),event('news',{sourceId:'ordinary',learning:undefined,title:'Company reports data breach'}),event('incident',{sourceId:'ordinary',category:'Incident',stream:'intelligence',learning:undefined})]));
  assert.deepEqual(filterEvents(data.events,{view:'research',now}).map(e=>e.id),['legacy','research']);
  for(const item of data.events.filter(e=>e.research))assert.equal(isNewsboardEvent(item),false);
  assert.deepEqual(filterEvents(data.events,{view:'newsboard',now}).map(e=>e.id),['news']);
  assert.deepEqual(filterEvents(data.events,{view:'newsletters',now}).map(e=>e.id),['news']);
  assert.deepEqual(filterEvents(data.events,{view:'feed',now}).map(e=>e.id),['incident']);
  assert.deepEqual(filterEvents(data.events,{view:'watchlist',savedIds:['research','incident'],now}).map(e=>e.id),['incident','research']);
});

test('research filters compose domain, perspective, source, query, date and reading status',()=>{
  const data=[event('a'),event('b',{learning:{...learning,domains:['ai']}}),event('old',{publishedAt:'2025-01-01'}),event('future',{publishedAt:'2026-11-01'}),event('ordinary',{learning:null})];
  const filter={query:'authorization server-side',domain:'web',perspective:'defensive',kind:'research',period:'7d',status:'saved',savedIds:new Set(['a','b']),source:'research-source',now};
  assert.deepEqual(filterResearchItems(data,filter).map(e=>e.id),['a']);
  assert.deepEqual(filterResearchItems(data,{status:'reviewed',reviewed:['a'],now}).map(e=>e.id),['a']);
  assert.deepEqual(filterResearchItems(data,{status:'following',followed:[],now}),[]);
  assert.equal(filterResearchItems(data,{status:'following',followed:['research-source'],now}).length,3);
  assert.ok(!filterResearchItems(data,{status:'unread',reviewed:['a'],now}).some(e=>e.id==='a'));
});

test('malformed research metadata is bounded and cannot invent a published release',()=>{
  assert.equal(normalizeLearning({kind:'unknown'}),null);
  const result=normalizeLearning({kind:'release',domains:['ai','invalid','ai'],perspectives:['offensive','root'],project:'x'.repeat(500),releaseStatus:'stable',dateBasis:'source-updated'});
  assert.deepEqual(result.domains,['ai']);assert.deepEqual(result.perspectives,['offensive']);assert.equal(result.project.length,180);assert.equal(result.releaseStatus,'unknown');assert.equal(result.dateBasis,'source-updated');
});

test('edition watch baselines and failed checks preserve the distinction from publication dates',()=>{
  const baseline={id:'watch-owasp',sourceId:'research-source',name:'OWASP',url:'https://owasp.org/',domains:['web'],currentLabel:'Published edition',publishedAt:null,firstObservedAt:'2026-10-30T10:00:00Z',lastCheckedAt:'2026-10-30T10:00:00Z',lastSuccessAt:'2026-10-30T10:00:00Z',changedAt:null,status:'ok',changeDetected:false,watchType:'edition',dateBasis:'observation'};
  const result=normalizeResearchWatch([baseline,{...baseline,id:'changed',changedAt:'2026-10-30T12:00:00Z',changeDetected:true},{...baseline,id:'false-change',changedAt:baseline.firstObservedAt,changeDetected:true},{...baseline,id:'error',status:'error',error:'Source unavailable'},{...baseline,id:'unsafe',url:'javascript:alert(1)'}],{sourceIds:new Set(['research-source'])});
  assert.equal(result.length,4);assert.equal(result[0].publishedAt,null);assert.equal(result[0].changeDetected,false);assert.equal(result[1].changeDetected,true);assert.equal(result[2].changeDetected,false);assert.equal(result[3].error,'Source unavailable');assert.equal(result[3].currentLabel,'Published edition');
  assert.deepEqual(normalizeResearchWatch([baseline],{sourceIds:new Set(['other'])}),[]);
});

test('watch normalization rejects impossible dates and unsafe URLs without creating dates',()=>{
  const item={id:'watch',sourceId:'research-source',name:'A project',url:'https://example.com/',publishedAt:'2026-02-31',lastCheckedAt:'not a date',firstObservedAt:null,referenceUrl:'data:text/html,unsafe'};
  const result=normalizeResearchWatch([item])[0];
  assert.equal(result.publishedAt,null);assert.equal(result.lastCheckedAt,null);assert.equal(result.referenceUrl,'https://example.com/');assert.equal(result.changeDetected,false);
  const observation=normalizeResearchWatch([{...item,publishedAt:'2026-10-30',dateBasis:'source-published',watchType:'edition'}])[0];
  assert.equal(observation.publishedAt,null);assert.equal(observation.dateBasis,'observation');
});

test('local learning state bounds notes, IDs and object keys',()=>{
  const value=JSON.parse('{"reviewed":["a","a","<script>"],"followed":["research-source"],"progress":{"web-api":["map","map"],"__proto__":["bad"]},"notes":{"web-api":"text"}}');
  value.notes.long='x'.repeat(5000);const result=normalizeResearchPreferences(value);
  assert.deepEqual(result.reviewed,['a']);assert.deepEqual(result.progress['web-api'],['map']);assert.equal(Object.hasOwn(result.progress,'__proto__'),false);assert.equal(result.notes.long.length,4000);
});

test('research export carries learning context and source update date semantics',()=>{
  const item=event('release',{learning:{...learning,kind:'release',releaseStatus:'prerelease',dateBasis:'source-updated'},title:'ASVS development release'});
  const csv=makeCSV([item]),brief=makeBrief(item);
  assert.match(csv,/"research"/);assert.match(csv,/"release","web; api","offensive; defensive","source-updated"/);
  assert.match(brief,/Source updated: 2026-10-29/);assert.match(brief,/Publication stream: Research Lab/);assert.doesNotMatch(brief,/Publication stream: Newsletter/);
});

test('all learning paths have actionable steps, paired perspectives and primary HTTPS resources',()=>{
  assert.equal(LEARNING_PATHS.length,6);
  for(const path of LEARNING_PATHS){assert.equal(path.steps.length,4);assert.ok(path.offensive&&path.defensive);assert.ok(path.links.length>=2);for(const [,url] of path.links)assert.equal(new URL(url).protocol,'https:');}
});

test('technique library combines lab methods, defensive checks and primary sources without invented release dates',()=>{
  assert.equal(TECHNIQUE_LIBRARY.length,24);
  assert.equal(new Set(TECHNIQUE_LIBRARY.map(item=>item.id)).size,24);
  const domains=new Set(TECHNIQUE_LIBRARY.flatMap(item=>item.domains));
  for(const domain of ['web','api','mobile','ai','cloud','identity','detection','general'])assert.ok(domains.has(domain));
  for(const item of TECHNIQUE_LIBRARY){
    assert.equal(item.method.length,3);assert.ok(item.defensive&&item.pitfall&&item.objective);
    assert.equal(item.dateBasis,'editorial-review');assert.equal(Object.hasOwn(item,'publishedAt'),false);
    assert.match(item.reviewedAt,/^\d{4}-\d{2}-\d{2}$/);assert.ok(item.links.length>=2);
    for(const [,link] of item.links)assert.equal(new URL(link).protocol,'https:');
  }
});

test('technique filters compose search, shared domain, experience and review status',()=>{
  assert.deepEqual(filterTechniques(TECHNIQUE_LIBRARY,{query:'retrieval tenant',domain:'ai',level:'intermediate'}).map(item=>item.id),['retrieval-access']);
  assert.deepEqual(filterTechniques(TECHNIQUE_LIBRARY,{domain:'web',level:'advanced'}).map(item=>item.id),['request-desync','cache-deception']);
  const reviewed=['object-authorization','agent-tool-authority'];
  assert.deepEqual(filterTechniques(TECHNIQUE_LIBRARY,{status:'reviewed',reviewed,domain:'ai'}).map(item=>item.id),['agent-tool-authority']);
  assert.equal(filterTechniques(TECHNIQUE_LIBRARY,{status:'unread',reviewed}).length,22);
  assert.deepEqual(filterTechniques(TECHNIQUE_LIBRARY,{query:'nonexistent-phrase'}),[]);
});

test('technique study state migrates from old preferences and rejects malformed IDs',()=>{
  assert.deepEqual(normalizeResearchPreferences({reviewed:['old-research'],progress:{mobile:['scope']}}).techniqueReviewed,[]);
  const result=normalizeResearchPreferences({techniqueReviewed:['object-authorization','object-authorization','<img>'],reviewed:['old-research']});
  assert.deepEqual(result.techniqueReviewed,['object-authorization']);assert.deepEqual(result.reviewed,['old-research']);
});
