/** Pure operational metrics and date navigation; no inferred trust scores. */
import { newsRelevance } from './news-relevance.js';
import { isResearchEvent } from './research-core.js';

export const DISPLAY_ZONE = 'Asia/Dhaka';
export const SOURCE_GROUP_LABELS = Object.freeze({intelligence:'Advisories & incidents',news:'Security reporting',newsboard:'World press',bangladesh:'Bangladesh',research:'Research & learning'});
export const QUALITY_LABELS = Object.freeze({ok:'Healthy',error:'Fetch error',stale:'Check overdue',manual:'Reviewed manually',unknown:'No check recorded'});
export const STALE_CHECK_MS = 2 * 60 * 60 * 1000;

export function normalizeSourceChecks(value) {
  const unique = new Map();
  for (const row of Array.isArray(value) ? value.slice(-48) : []) {
    if (!row || !['ok','error'].includes(row.status) || typeof row.at !== 'string' || !/^\d{4}-\d{2}-\d{2}T.+(?:Z|[+-]\d{2}:\d{2})$/.test(row.at) || !Number.isFinite(Date.parse(row.at))) continue;
    if (!Number.isInteger(row.recordCount) || row.recordCount < 0 || row.recordCount > 2000) continue;
    const at = new Date(row.at).toISOString();
    unique.set(at,{at,status:row.status,recordCount:row.recordCount});
  }
  return [...unique.values()].sort((a,b)=>a.at.localeCompare(b.at)).slice(-48);
}

export function sourceQualityRows(data, {now=Date.now()}={}) {
  const bySource = new Map();
  for (const event of data?.events || []) {
    if (!bySource.has(event.sourceId)) bySource.set(event.sourceId,[]);
    bySource.get(event.sourceId).push(event);
  }
  return (data?.sources || []).map(source=>{
    const events=bySource.get(source.id)||[], manual=source.kind==='curated';
    const attempt=Date.parse(source.lastAttemptAt||'');
    const overdue=!manual&&Number.isFinite(attempt)&&now-attempt>STALE_CHECK_MS;
    const status=manual?'manual':source.status==='error'?'error':overdue?'stale':source.status==='ok'&&Number.isFinite(attempt)?'ok':'unknown';
    let checks=normalizeSourceChecks(source.collectionHistory);
    if(!checks.length&&!manual&&['ok','error'].includes(source.status)&&Number.isFinite(attempt))checks=[{at:new Date(attempt).toISOString(),status:source.status,recordCount:events.length}];
    const successes=checks.filter(row=>row.status==='ok').length;
    const coverage={full:0,excerpt:0,restricted:0,unavailable:0};
    for(const event of events)coverage[['full','excerpt','restricted'].includes(event.article?.status)?event.article.status:'unavailable']++;
    const dated=events.map(event=>event.publishedAt).filter(Boolean).sort((a,b)=>Date.parse(b)-Date.parse(a));
    const relevant=events.filter(event=>!isResearchEvent(event)&&((event.category==='News'||event.stream==='news')?newsRelevance(event).relevant:true)).length;
    return {...source,events,manual,status,overdue,checks,successes,successRate:checks.length?Math.round(successes/checks.length*100):null,coverage,newestPublication:dated[0]||null,relevant,recordCount:events.length};
  });
}

export function filterQualityRows(rows,{query='',status='all',group='all',sort='attention'}={}) {
  const terms=query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  const priority={error:0,stale:1,unknown:2,ok:3,manual:4};
  return rows.filter(row=>(status==='all'||status==='attention'&&['error','stale','unknown'].includes(row.status)||row.status===status)&&
    (group==='all'||row.group===group)&&terms.every(term=>`${row.name} ${row.id} ${row.description||''} ${row.error||''}`.toLowerCase().includes(term)))
    .sort((a,b)=>(sort==='records'?b.recordCount-a.recordCount:sort==='coverage'?(b.recordCount?b.coverage.full/b.recordCount:-1)-(a.recordCount?a.coverage.full/a.recordCount:-1):sort==='name'?0:priority[a.status]-priority[b.status])||a.name.localeCompare(b.name));
}

export function qualitySummary(rows) {
  const automatic=rows.filter(row=>!row.manual),checks=automatic.flatMap(row=>row.checks);
  const records=rows.reduce((sum,row)=>sum+row.recordCount,0),full=rows.reduce((sum,row)=>sum+row.coverage.full,0);
  return {total:rows.length,automatic:automatic.length,healthy:automatic.filter(row=>row.status==='ok').length,
    errors:automatic.filter(row=>row.status==='error').length,overdue:automatic.filter(row=>row.overdue).length,
    samples:checks.length,successes:checks.filter(row=>row.status==='ok').length,records,full};
}

function csvCell(value) {
  let text=String(value??'');
  if(/^[=+@\-\t\r]/.test(text))text="'"+text;
  return '"'+text.replaceAll('"','""')+'"';
}
export function makeQualityCSV(rows) {
  const columns=['Source','Group','Provenance','Latest collection state','Last attempt','Last success','Recorded checks','Successful checks','Success %','Displayed records','Full text','Excerpt','Publisher restricted','Source/context only','Newest source date','Latest error'];
  return [columns,...rows.map(row=>[row.name,SOURCE_GROUP_LABELS[row.group]||row.group,row.kind,QUALITY_LABELS[row.status],row.lastAttemptAt,row.lastSuccessAt,row.checks.length,row.successes,row.successRate,row.recordCount,row.coverage.full,row.coverage.excerpt,row.coverage.restricted,row.coverage.unavailable,row.newestPublication,row.error])].map(row=>row.map(csvCell).join(',')).join('\r\n');
}

/** Date-only source values keep their calendar date; timestamps use BDT. */
export function calendarDate(value) {
  if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}(?:$|T)/.test(value)||!Number.isFinite(Date.parse(value)))return '';
  const [year,month,day]=value.slice(0,10).split('-').map(Number);
  if(month<1||month>12||day<1||day>new Date(Date.UTC(year,month,0)).getUTCDate())return '';
  if(value.length===10)return value;
  const parts=new Intl.DateTimeFormat('en-CA',{timeZone:DISPLAY_ZONE,year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date(value));
  return ['year','month','day'].map(type=>parts.find(part=>part.type===type)?.value).join('-');
}

export function isMajorRecord(event) {
  return event.category==='Incident'||event.exploited===true||['critical','high'].includes(event.severity);
}

export function historyItems(data,{basis='milestones',scope='major',category='all',query=''}={}) {
  const sources=new Map((data?.sources||[]).map(source=>[source.id,source]));
  const terms=query.trim().toLowerCase().split(/\s+/).filter(Boolean),items=[],seen=new Set();
  for(const event of data?.events||[]) {
    if(isResearchEvent(event))continue;
    const source=sources.get(event.sourceId),news=event.stream==='news'||event.category==='News';
    if(news&&!newsRelevance(event).relevant)continue;
    if(scope==='major'&&!isMajorRecord(event))continue;
    if(category!=='all'&&event.category!==category)continue;
    if(basis==='milestones'&&source?.kind!=='curated')continue;
    const entries=basis==='publications'?[{date:event.publishedAt,title:source?.id==='cisa-kev'?'Added to CISA KEV':event.learning?.dateBasis==='source-updated'?'Source update':'Published / disclosed',description:event.summary}]:event.timeline||[];
    for(const entry of entries) {
      const day=calendarDate(entry.date);
      if(!day)continue;
      if(!terms.every(term=>`${event.title} ${event.organization} ${source?.name||''} ${event.cves?.join(' ')} ${entry.title} ${entry.description}`.toLowerCase().includes(term)))continue;
      const id=`${event.id}|${day}|${entry.title}`;
      if(seen.has(id))continue;
      seen.add(id);items.push({id,day,event,source,title:entry.title,description:entry.description,basis,date:entry.date,major:isMajorRecord(event)});
    }
  }
  return items.sort((a,b)=>b.day.localeCompare(a.day)||Number(b.major)-Number(a.major)||a.event.title.localeCompare(b.event.title)||a.title.localeCompare(b.title));
}

export function makeHistoryCSV(items) {
  const columns=['Date basis','Calendar date (BDT for timestamps)','Source date value','Milestone / publication','Record ID','Title','Category','Severity','Organization','Publisher','Context','Source URLs'];
  return [columns,...items.map(item=>[item.basis,item.day,item.date,item.title,item.event.id,item.event.title,item.event.category,item.event.severity,item.event.organization,item.source?.name||'',item.description,(item.event.sources||[]).map(source=>source.url).join(' | ')])].map(row=>row.map(csvCell).join(',')).join('\r\n');
}

export function shiftMonth(month,delta) {
  if(!/^\d{4}-(?:0[1-9]|1[0-2])$/.test(month)||!Number.isInteger(delta))return '';
  const [year,m]=month.split('-').map(Number),date=new Date(Date.UTC(year,m-1+delta,1));
  return date.toISOString().slice(0,7);
}

export function monthCalendar(month) {
  if(!/^\d{4}-(?:0[1-9]|1[0-2])$/.test(month))return [];
  const [year,m]=month.split('-').map(Number),first=new Date(Date.UTC(year,m-1,1));
  const leading=(first.getUTCDay()+6)%7,days=new Date(Date.UTC(year,m,0)).getUTCDate();
  return Array.from({length:Math.ceil((leading+days)/7)*7},(_,index)=>{
    const date=new Date(Date.UTC(year,m-1,index-leading+1)),day=date.toISOString().slice(0,10);
    return {day,number:date.getUTCDate(),inMonth:day.startsWith(month)};
  });
}
