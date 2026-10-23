import { escapeHTML as h, safeURL, normalizeData, filterEvents, isNewsEvent, isBangladeshEvent, makeCSV, makeBrief, cveURL, relatedEvents } from './core.js';
import { createFeedClient } from './refresh.js';

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const ICONS = {
  activity:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  bookmark:'<path d="M6 4h12v17l-6-4-6 4z"/>',
  radio:'<circle cx="12" cy="12" r="2"/><path d="M7 7a7 7 0 0 0 0 10M17 7a7 7 0 0 1 0 10M4 4a11 11 0 0 0 0 16M20 4a11 11 0 0 1 0 16"/>',
  layers:'<path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5"/>',
  shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  grid:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  download:'<path d="M12 3v12m-4-4 4 4 4-4M4 15v5h16v-5"/>',
  refresh:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 7a7 7 0 0 1 11.5-2L20 8M4 16l2.4 3A7 7 0 0 0 18 17"/>',
  alert:'<path d="m12 3 10 17H2L12 3Z"/><path d="M12 9v5m0 3v.1"/>',
  crosshair:'<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3"/>',
  search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  filter:'<path d="M3 5h18M6 12h12m-9 7h6"/><circle cx="8" cy="5" r="2"/><circle cx="16" cy="12" r="2"/>',
  calendar:'<rect x="4" y="5" width="16" height="16" rx="2"/><path d="M8 3v4m8-4v4M4 10h16m-11 4h1m4 0h1m-6 3h1"/>',
  reset:'<path d="M4 10a8 8 0 1 1 1 8M4 4v6h6"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.1"/>',
  close:'<path d="m6 6 12 12M18 6 6 18"/>',
  arrow:'<path d="M4 12h16m-6-6 6 6-6 6"/>',
  chevron:'<path d="m9 5 7 7-7 7"/>',
  copy:'<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  link:'<path d="m10 13 4-4m-6 6-2 2a4 4 0 0 1-6-6l5-5a4 4 0 0 1 6 0m2 3 2-2a4 4 0 0 1 6 6l-5 5a4 4 0 0 1-6 0" transform="translate(2 1) scale(.85)"/>',
  external:'<path d="M14 3h7v7m0-7L10 14M10 3H3v18h18v-7"/>',
  file:'<path d="M14 3H5v18h14V8l-5-5Zm0 0v5h5M8 12h8m-8 4h6"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  newspaper:'<path d="M4 4h16v16H4zM8 8h8M8 12h3m3 0h2M8 16h3m3 0h2"/>',
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a17 17 0 0 1 0 18 17 17 0 0 1 0-18Z"/>',
  database:'<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0"/>',
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ICONS.file}</svg>`;
function hydrateIcons(root = document) { root.querySelectorAll('[data-icon]').forEach(el => { el.innerHTML = icon(el.dataset.icon); }); }
hydrateIcons();

const state = {data:null,view:'feed',query:'',severity:'all',category:'all',period:'all',source:'all',regionScope:'all',sort:'newest',tab:'all',limit:12,selectedId:null,detailTab:'overview',saved:new Set(),loading:false,browserCheckedAt:null,browserAttemptAt:null,refreshFailed:false};
Object.assign(state,{initializing:true,collecting:false,collectionMessage:'',collectionWarning:false,configurationWarning:'',collectionNoticeUntil:0});
let feedClient;
// Retain the established storage key so renaming the app preserves saved events.
const STORAGE_KEY = 'sentinel.watchlist.v1';
let storageAvailable = true;
try {
  const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  if (Array.isArray(stored)) state.saved = new Set(stored.filter(id => typeof id === 'string' && id.length <= 180).slice(0,500));
} catch { storageAvailable = false; }
let toastTimer;
function toast(message) {
  const el = $('#toast');
  const host=$('#event-dialog').open?$('#event-dialog'):$('#info-dialog').open?$('#info-dialog'):document.body;
  if(el.parentElement!==host)host.appendChild(el);
  el.textContent = message; el.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.hidden = true; },4500);
}
const DISPLAY_ZONE = 'Asia/Dhaka';
const shortDate = value => new Intl.DateTimeFormat('en-US',{month:'short',day:'2-digit',timeZone:DISPLAY_ZONE}).format(new Date(value));
const fullDate = value => value ? new Intl.DateTimeFormat('en-GB',{day:'2-digit',month:'short',year:'numeric',timeZone:DISPLAY_ZONE}).format(new Date(value)) : 'Not available';
const fullTimestamp = value => value ? new Intl.DateTimeFormat('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23',timeZone:DISPLAY_ZONE}).format(new Date(value))+' BDT' : 'Not recorded';
const severityText = severity => severity === 'unknown' ? 'UNRATED' : severity.toUpperCase();
const severityBadge = severity => `<span class="badge severity-${h(severity)}">${h(severityText(severity))}</span>`;
const eventBadge = event => isNewsEvent(event) ? '<span class="badge news-badge">UPDATE</span>' : severityBadge(event.severity);
const scopeLabels = {'national-advisory':'National advisory','local-activity':'Local activity',coverage:'News coverage'};
const initials = organization => organization.replace(/[^a-z0-9]/gi,'').slice(0,2).toUpperCase() || 'SI';
const countFormat = count => String(count).padStart(2,'0');
const sourceState = source => source.status === 'ok' ? 'COLLECTED' : source.status === 'error' ? 'FETCH ERROR' : 'REVIEWED';
function sourceDescription(source) {
  if (source.description) return source.description;
  if (source.group === 'news') return 'Public publisher updates and short feed excerpts. Open the original article for the complete report; an article is not an independently verified incident.';
  if (source.group === 'bangladesh') return 'Bangladesh advisories and documented cyber activity. The record identifies whether it is a national advisory, a local activity report, or news coverage.';
  if (source.kind === 'curated') return 'Researched incident reports and vendor disclosures with event-specific impact, recommendations, and evidence notes. Each report links to its original evidence.';
  if (/cisa|kev/i.test(source.id+' '+source.name)) return 'CISA’s Known Exploited Vulnerabilities catalog. Entries confirm exploitation evidence; they do not provide a severity score or establish compromise in your environment.';
  if (/chrome|google/i.test(source.id+' '+source.name)) return 'Official Chrome release announcements with security fixes. Included releases are selected for security relevance and linked to their original publication.';
  return 'Official security advisories collected from the publisher’s feed. Source summaries and analyst triage guidance are identified within each event.';
}
function visibleEvents() {
  let events = filterEvents(state.data?.events || [], {...state,savedIds:state.saved});
  if (state.tab === 'priority') events = events.filter(event => ['critical','high'].includes(event.severity));
  if (state.tab === 'exploited') events = events.filter(event => event.exploited);
  return events;
}
function updateClock() { $('#utc-clock').textContent = new Intl.DateTimeFormat('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23',timeZone:DISPLAY_ZONE}).format(new Date())+' BDT'; }
updateClock(); setInterval(updateClock,1000);

function scopedEvents() {
  return filterEvents(state.data?.events || [], {view:state.view,savedIds:state.saved});
}
function scopedSources(events=scopedEvents()) {
  const ids=new Set(events.map(event=>event.sourceId));
  if(state.view==='sources')return state.data.sources;
  return state.data.sources.filter(source=>ids.has(source.id) || (state.view==='newsletters'&&source.group==='news') || (state.view==='bangladesh'&&source.group==='bangladesh') || (state.view==='feed'&&source.group==='intelligence'));
}
function renderFreshness() {
  const writeTime=(id,value,empty='Not recorded')=>{const el=$(id);el.textContent=value?fullTimestamp(value):empty;if(value){el.dateTime=value;el.title=value;}else{el.removeAttribute('datetime');el.removeAttribute('title');}};
  writeTime('#database-updated',state.data?.databaseUpdatedAt);
  writeTime('#feed-checked',state.data?.lastCheckedAt);
  writeTime('#browser-checked',state.browserCheckedAt,'Not loaded');
  const channels=(state.data?.sources || []).filter(source=>source.kind!=='curated');
  const errors=channels.filter(source=>source.status==='error').length;
  $('#feed-check-result').textContent=state.data?.lastCheckedAt?`${channels.length-errors}/${channels.length} channels available · ${errors?errors+' check'+(errors===1?'':'s')+' failed':'every 30 minutes'}`:'No collection attempt recorded';
  $('#feed-check-result').classList.toggle('freshness-warning',errors>0);
  $('#browser-check-result').textContent=state.refreshFailed?`Refresh failed at ${fullTimestamp(state.browserAttemptAt)}; previous data retained.`:'This browser · Bangladesh time (UTC+06:00)';
  $('#browser-check-result').classList.toggle('freshness-warning',state.refreshFailed);
}

function renderStats() {
  const events=scopedEvents(),sources=scopedSources(events),all=state.data.events;
  const priority = events.filter(event => ['critical','high'].includes(event.severity)).length;
  const exploited = events.filter(event => event.exploited).length;
  const news=state.view==='newsletters',bd=state.view==='bangladesh';
  $('#stat-total-label').textContent=news?'PUBLISHER UPDATES':bd?'BANGLADESH RECORDS':'TRACKED EVENTS';
  $('#stat-priority-label').textContent=news?'PUBLISHED · 7 DAYS':bd?'NATIONAL ADVISORIES':'CRITICAL & HIGH';
  $('#stat-exploited-label').textContent=news?'CVE REFERENCES':bd?'LOCAL ACTIVITY':'KNOWN EXPLOITATION';
  $('#stat-sources-label').textContent=news?'NEWS PUBLISHERS':'SOURCE CHANNELS';
  $('#stat-total').textContent=countFormat(events.length);
  $('#stat-priority').textContent=countFormat(news?events.filter(event=>Date.parse(event.publishedAt)>=Date.now()-604800000).length:bd?events.filter(event=>event.bangladeshScope==='national-advisory').length:priority);
  $('#stat-exploited').textContent=countFormat(news?events.filter(event=>event.cves.length).length:bd?events.filter(event=>event.bangladeshScope==='local-activity').length:exploited);
  $('#stat-sources').textContent=countFormat(sources.length);
  $('#stat-priority').classList.toggle('danger',!news&&!bd);
  $('#stat-exploited').classList.toggle('amber',!news&&!bd);
  $('#stat-total-note').textContent=news?'Public news, research & release notes':bd?'Advisories, reports & defensive activity':`${events.filter(event=>event.category==='Incident').length} incident reports · current view`;
  $('#stat-priority-note').textContent=news?'Based on original publication dates':bd?'Guidance for organizations in Bangladesh':'Priority review · source-rated or assessed';
  $('#stat-exploited-note').textContent=news?'Updates mentioning CVE identifiers':bd?'Reported threats or defensive activity':'Reported exploitation in the wild';
  const failed=sources.filter(source=>source.status==='error').length;
  $('#stat-sources-note').textContent=failed ? `${failed} channel${failed===1?'':'s'} need attention` : 'Publication & collection dates preserved';
  $('#nav-feed-count').textContent=filterEvents(all,{view:'feed'}).length;
  $('#nav-news-count').textContent=filterEvents(all,{view:'newsletters'}).length;
  $('#nav-bd-count').textContent=filterEvents(all,{view:'bangladesh'}).length;
  $('#nav-source-count').textContent=state.data.sources.length;
  $('#nav-saved-count').textContent=all.filter(event=>state.saved.has(event.id)).length;
  const collections={Incident:'incidents',Vulnerability:'vulns',Patch:'patches',Advisory:'advisories'};
  for (const [category,id] of Object.entries(collections)) $(`#collection-${id}`).textContent=all.filter(event=>event.category===category&&!isNewsEvent(event)).length;
  $('#tab-all-count').textContent=events.length;
  $('#tab-priority-count').textContent=events.filter(event=>['critical','high'].includes(event.severity)).length;
  $('#tab-exploited-count').textContent=events.filter(event=>event.exploited).length;
}

function renderInsights() {
  const events=scopedEvents(),sources=scopedSources(events);
  const news=state.view==='newsletters';
  const ordered=filterEvents(events,{view:'all',sort:news?'newest':'severity'});
  const spotlight=(!news&&ordered.find(event=>event.exploited&&['curated','bangladesh-curated'].includes(event.sourceId))) || ordered[0];
  $('#radar-title').textContent=news?'LATEST PUBLICATION':state.view==='bangladesh'?'BANGLADESH FOCUS':'ON YOUR RADAR';
  $('#priority-brief').innerHTML=spotlight ? `<div class="priority-org">${eventBadge(spotlight)}<span>${h(spotlight.organization)}</span></div><h3 class="priority-title">${h(spotlight.title)}</h3><p class="priority-summary">${h(spotlight.summary.length>155?spotlight.summary.slice(0,152)+'…':spotlight.summary)}</p><button class="priority-link" data-open-event="${h(spotlight.id)}">${news?'Read publisher brief':'View assessment'} ${icon('arrow')}</button>` : '<p class="priority-summary">No events are available in this snapshot.</p>';
  const categories=['Incident','Vulnerability','Patch','Advisory',...(events.some(isNewsEvent)?['News']:[])];
  $('#signal-breakdown').innerHTML=categories.map(category=>{
    const count=events.filter(event=>event.category===category).length;
    return `<div class="signal-item"><div class="signal-label"><span><span class="tiny-dot ${category==='Incident'?'incident':category==='Vulnerability'?'vulnerability':category==='Patch'?'patch':'advisory'}-dot"></span>${category==='Vulnerability'?'Vulnerabilities':category==='Advisory'?'Advisories':category==='Patch'?'Security patches':category==='News'?'Publisher updates':'Incidents'}</span><span>${countFormat(count)}</span></div><div class="signal-track"><div class="signal-fill ${category}" data-percent="${events.length?Math.round(count/events.length*100):0}"></div></div></div>`;
  }).join('');
  $$('.signal-fill').forEach(el=>{el.style.width=`${Number(el.dataset.percent)}%`;});
  if(news){$('#signal-breakdown').innerHTML=sources.slice(0,6).map(source=>`<div class="publisher-breakdown"><span>${h(source.name)}</span><strong>${countFormat(events.filter(event=>event.sourceId===source.id).length)}</strong></div>`).join('');}
  $('.insight-caption').textContent=news?'Updates by publisher · current snapshot':'By event type · current view';
  $('#source-health').innerHTML=sources.slice(0,5).map(source=>`<div class="source-status-row"><span class="tiny-dot ${source.status==='error'?'vulnerability':'patch'}-dot"></span><span>${h(source.name)}</span><span class="source-state ${source.status==='error'?'error':''}">${sourceState(source)}</span></div>`).join('')+(sources.length>5?`<p class="more-source-note">+ ${sources.length-5} channels in Sources</p>`:'');
  $('#snapshot-time').textContent=`Last feed check ${fullTimestamp(state.data.lastCheckedAt)}`;
}

function renderPublisherChannels() {
  const sources=scopedSources();
  $('#publisher-filter').innerHTML='<option value="all">All publishers</option>'+sources.map(source=>`<option value="${h(source.id)}">${h(source.name)}</option>`).join('');
  $('#publisher-filter').value=state.source;
  if(state.view!=='newsletters')return;
  $('#publisher-channels').innerHTML=sources.filter(source=>source.group==='news').map(source=>`<button class="publisher-channel ${state.source===source.id?'active':''}" data-source-filter="${h(source.id)}" aria-pressed="${state.source===source.id}" title="Browse ${h(source.name)} updates"><span class="publisher-monogram" aria-hidden="true">${h(initials(source.name))}</span><span class="publisher-channel-text"><strong>${h(source.name)}</strong><small><span class="tiny-dot ${source.status==='error'?'vulnerability':'patch'}-dot"></span>${source.status==='error'?'Check failed':source.kind==='curated'?'Reviewed reports':source.itemCount+' updates'}</small></span>${icon('chevron')}</button>`).join('');
}

function renderEventList() {
  if(!state.data)return;
  const events=visibleEvents();
  const displayed=events.slice(0,state.limit);
  const news=state.view==='newsletters';
  $('#result-count').textContent=`${events.length} ${news?'UPDATE':'EVENT'}${events.length===1?'':'S'}`;
  $('#console-title').textContent=state.view==='watchlist'?'watchlist.log':news?'publisher-updates.log':state.view==='bangladesh'?'bangladesh-watch.log':'incident-stream.log';
  $('.console-panel').classList.toggle('newsletter-mode',news);
  $('.event-column-labels').hidden=news;
  $('#event-list').classList.toggle('newsletter-grid',news);
  const chips=[];
  if(state.category!=='all') chips.push(state.category);
  if(state.source!=='all') chips.push(state.data.sources.find(source=>source.id===state.source)?.name || state.source);
  if(state.query) chips.push(`“${state.query.length>25?state.query.slice(0,25)+'…':state.query}”`);
  if(state.regionScope!=='all')chips.push(scopeLabels[state.regionScope]||state.regionScope);
  $('#active-filters').innerHTML=chips.length?chips.map(chip=>`<span class="filter-chip">${h(chip)}</span>`).join(''):news?'LATEST PUBLISHER UPDATES':state.view==='bangladesh'?'BANGLADESH INTELLIGENCE':'LATEST INTELLIGENCE';
  $('#event-list').setAttribute('aria-busy','false');
  if(!events.length) {
    const savedEmpty=state.view==='watchlist'&&!state.data.events.some(event=>state.saved.has(event.id));
    $('#event-list').innerHTML=`<div class="empty-state"><span>${icon(savedEmpty?'bookmark':'search')}</span><h3>${savedEmpty?'Your watchlist starts here.':'No matching signals.'}</h3><p>${savedEmpty?'Open an event and use the bookmark button to keep it in your personal watchlist.':'Try a different keyword, date range, or severity. Your filters work together.'}</p><button class="button secondary" data-empty-action="${savedEmpty?'feed':'reset'}">${savedEmpty?'Explore incident feed':'Clear filters'} ${icon('arrow')}</button></div>`;
  } else if(news) {
    $('#event-list').innerHTML=displayed.map(event=>{
      const publisher=state.data.sources.find(source=>source.id===event.sourceId)?.name || event.organization;
      const original=event.sources.find(source=>safeURL(source.url));
      return `<article class="newsletter-card"><div class="newsletter-meta"><span class="publisher-mini">${h(publisher)}</span><time datetime="${h(event.publishedAt)}" title="${h(fullDate(event.publishedAt))}">${h(shortDate(event.publishedAt))}</time></div><h3><button data-open-event="${h(event.id)}">${h(event.title)}</button></h3><p>${h(event.summary||'The publisher provides the complete report on its website.')}</p><div class="newsletter-tags">${event.cves.slice(0,2).map(cve=>`<span>${h(cve)}</span>`).join('')}${isBangladeshEvent(event)?'<span>Bangladesh</span>':''}</div><div class="newsletter-actions"><button data-open-event="${h(event.id)}">Read brief ${icon('arrow')}</button>${original?`<a href="${h(safeURL(original.url))}" target="_blank" rel="noopener noreferrer" aria-label="Read original article: ${h(event.title)}">Original ${icon('external')}</a>`:''}${state.saved.has(event.id)?`<span title="Saved to watchlist">${icon('bookmark')}</span>`:''}</div></article>`;
    }).join('');
  } else {
    $('#event-list').innerHTML=displayed.map(event=>`<button class="event-row" data-open-event="${h(event.id)}" aria-label="${h(event.title)}. ${isNewsEvent(event)?'Publisher update':h(severityText(event.severity))+' severity'}. Open details."><span class="event-date">${h(shortDate(event.publishedAt))}<small>${new Intl.DateTimeFormat('en',{year:'numeric',timeZone:DISPLAY_ZONE}).format(new Date(event.publishedAt))} · BDT</small></span><span class="event-severity">${eventBadge(event)}</span><span class="event-body"><span class="event-title">${h(event.title)}</span><span class="event-meta"><span class="org-icon" aria-hidden="true">${h(initials(event.organization))}</span><span class="org-name">${h(event.organization)}</span><span class="meta-sep" aria-hidden="true"></span><span class="event-type">${h(state.view==='bangladesh'&&event.bangladeshScope?scopeLabels[event.bangladeshScope]:event.category)}</span>${event.exploited?`<span class="exploit-tag">${icon('crosshair')} EXPLOITED</span>`:''}</span></span><span class="source-count" title="${event.sources.length} source links">${icon('link')}${event.sources.length}</span><span class="row-arrow">${icon('chevron')}</span>${state.saved.has(event.id)?`<span class="row-saved" aria-label="Saved to watchlist">${icon('bookmark')}</span>`:''}</button>`).join('');
  }
  $('#console-footer-text').textContent=`${displayed.length} of ${events.length} ${news?'updates':'events'} · source dates · Bangladesh time`;
  $('#load-more').hidden=displayed.length>=events.length;
  $('#export-button').disabled=!events.length;
  $$('.feed-tab').forEach(button=>{button.classList.toggle('active',button.dataset.feedTab===state.tab);button.setAttribute('aria-pressed',String(button.dataset.feedTab===state.tab));});
  $$('.collection-nav button').forEach(button=>{button.classList.toggle('active',button.dataset.collection===state.category);button.setAttribute('aria-pressed',String(button.dataset.collection===state.category));});
  $$('.region-tab').forEach(button=>{const active=button.dataset.regionScope===state.regionScope;button.classList.toggle('active',active);button.setAttribute('aria-pressed',String(active));});
  $$('.publisher-channel').forEach(button=>{const active=button.dataset.sourceFilter===state.source;button.classList.toggle('active',active);button.setAttribute('aria-pressed',String(active));});
  $('#publisher-filter').value=state.source;
}

function renderSources() {
  $('#source-cards').innerHTML=state.data.sources.map(source=>`<article class="source-card"><div class="source-card-top"><span class="source-card-icon">${icon(source.group==='news'?'newspaper':source.group==='bangladesh'?'globe':source.kind==='curated'?'shield':'radio')}</span><span class="source-state ${source.status==='error'?'error':''}">${sourceState(source)}</span></div><span class="source-group">${source.group==='news'?'NEWS & RESEARCH':source.group==='bangladesh'?'BANGLADESH':'GLOBAL INTELLIGENCE'} · ${source.kind==='secondary'?'SECONDARY REPORTING':source.kind==='curated'?'REVIEWED RECORDS':'PRIMARY PUBLISHER'}</span><h3>${h(source.name)}</h3><p>${h(sourceDescription(source))}</p>${source.error?`<p class="source-card-error">${h(source.error)}. Last available records are shown where retained.</p>`:''}<div class="source-facts"><div><small>RECORDS</small>${countFormat(source.itemCount)}</div><div><small>${source.kind==='curated'?'METHOD':'LAST SUCCESSFUL FETCH'}</small>${h(source.kind==='curated'?'Editorial review':source.lastSuccessAt?fullTimestamp(source.lastSuccessAt):'Not yet collected')}</div><div><small>LAST CHECK ATTEMPT</small>${h(source.kind==='curated'?'Manually reviewed':source.lastAttemptAt?fullTimestamp(source.lastAttemptAt):'Not recorded')}</div></div><div class="source-card-actions"><button data-source-filter="${h(source.id)}">Browse updates ${icon('arrow')}</button>${source.url?`<a href="${h(safeURL(source.url))}" target="_blank" rel="noopener noreferrer">Open source ${icon('external')}</a>`:'<span>Direct links in event details</span>'}</div></article>`).join('');
}

function render() {
  if(!state.data) return;
  renderFreshness();renderStats();renderPublisherChannels();renderEventList();renderInsights();renderSources();
}

function setView(view,{reset=false,updateHash=true}={}) {
  state.view=['feed','newsletters','bangladesh','watchlist','sources'].includes(view)?view:'feed';
  if(reset)resetFilters(false);
  state.limit=12;
  const labels={feed:['Incident feed','Incident intelligence','Recent cyber events. Verified sources. Actionable context.'],newsletters:['Newsletters & updates','Newsletters & updates','Security news, threat research, and release notes from the publishers you follow.'],bangladesh:['Bangladesh','Bangladesh cyber watch','National advisories, local cyber activity, and developments relevant to Bangladesh.'],watchlist:['Watchlist','Your watchlist','Keep the signals that matter close. Saved on this browser.'],sources:['Sources','Intelligence sources','Know where your information comes from — and when it was checked.']};
  const [crumb,title,description]=labels[state.view];
  $('#breadcrumb-current').textContent=crumb;
  $('#page-title').innerHTML=`${h(title)}<span class="heading-dot">.</span>`;
  $('#page-description').textContent=description;
  $('#feed-view').hidden=state.view==='sources';
  $('#sources-view').hidden=state.view!=='sources';
  $('#export-button').hidden=state.view==='sources';
  $('#publisher-channels').hidden=state.view!=='newsletters';
  $('#bangladesh-context').hidden=state.view!=='bangladesh';
  $('.feed-tabs').hidden=state.view==='newsletters';
  $('#severity-filter-wrap').hidden=state.view==='newsletters';
  $('#publisher-filter-wrap').hidden=!['newsletters','bangladesh'].includes(state.view);
  $('#sort-select option[value="severity"]').hidden=state.view==='newsletters';
  $('#search-input').placeholder=state.view==='newsletters'?'Search articles, publishers, CVEs…':state.view==='bangladesh'?'Search Bangladesh advisories and activity…':'Search events, CVEs, organizations…';
  $$('.nav-item').forEach(button=>{const active=button.dataset.view===state.view;button.classList.toggle('active',active);if(active)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');});
  if(updateHash)history.replaceState(null,'',`#${state.view}`);
  render();
}
function resetFilters(shouldRender=true) {
  Object.assign(state,{query:'',severity:'all',category:'all',period:'all',source:'all',regionScope:'all',sort:'newest',tab:'all',limit:12});
  $('#search-input').value='';$('#severity-filter').value='all';$('#period-filter').value='all';$('#sort-select').value='newest';$('#publisher-filter').value='all';
  if(shouldRender)renderEventList();
}

function detailDate(value) {
  if(!value)return 'Not recorded';
  return value.includes('T')?fullTimestamp(value):`${fullDate(value)} · date only`;
}
function detailList(items, fallback, ordered=false) {
  if(!items?.length)return `<p class="detail-unavailable">${h(fallback)}</p>`;
  const tag=ordered?'ol':'ul';
  return `<${tag} class="${ordered?'recommendation-list':'detail-facts-list'}">${items.map(item=>`<li>${h(item)}</li>`).join('')}</${tag}>`;
}
function detailProvenance(event) {
  const channel=state.data.sources.find(source=>source.id===event.sourceId);
  const curated=channel?.kind==='curated';
  const status=curated?'Curated record':channel?.status==='ok'?'Last fetch succeeded':channel?.status==='error'?'Last fetch failed':'Snapshot record';
  return `<section class="detail-section detail-provenance"><h3>${icon('database')} Publication & collection</h3><div class="detail-channel"><span>${h(channel?.name||event.sourceId)}</span><span class="detail-collection-state ${channel?.status==='error'?'is-error':''}">${h(status)}</span></div><dl class="detail-record-grid"><div><dt>FIRST PUBLISHED</dt><dd>${h(detailDate(event.publishedAt))}</dd></div><div><dt>RECORD UPDATED</dt><dd>${h(detailDate(event.updatedAt))}</dd></div><div><dt>LAST SUCCESSFUL FEED FETCH</dt><dd>${curated?'Not applicable · curated':h(detailDate(channel?.lastSuccessAt))}</dd></div><div><dt>LAST FEED CHECK ATTEMPT</dt><dd>${curated?'Not applicable · curated':h(detailDate(channel?.lastAttemptAt))}</dd></div></dl><p class="detail-caption">${curated?'This record is maintained from the linked original sources. Automatic feed checks do not re-verify its assessment.':'Fetch times describe this source channel, not the time of the incident or a verification of every claim. A successful check may return no new articles.'}</p>${channel?.status==='error'?'<p class="detail-fetch-warning">The latest source check failed. This record is retained from the available snapshot; consult the original publication for newer developments.</p>':''}</section>`;
}
function detailTechnical(event) {
  const details=event.technicalDetails;
  if(!details)return `<section class="detail-section"><h3>${icon('crosshair')} Technical context</h3><div class="detail-empty-context"><p>Affected versions, attack prerequisites and detection indicators are not specified in this record.</p><p>Use the linked source to establish local exposure. A missing indicator or exploitation claim does not establish that a system is safe.</p></div></section>`;
  const cards=[
    ['affectedSystems','Affected systems & versions','No affected product or version range is stated in this record.'],
    ['attackVector','Attack vector','The source does not disclose the technical entry point.'],
    ['prerequisites','Exposure conditions','Specific exploitation prerequisites have not been established.'],
    ['mitigation','Mitigation & response','No source-specific mitigation is recorded; consult the original advisory.'],
  ];
  return `<section class="detail-section"><h3>${icon('crosshair')} Technical context <span class="detail-section-label">SOURCE CONTEXT</span></h3>${details.reviewedAt?`<p class="detail-caption">Context reviewed ${h(detailDate(details.reviewedAt))}. Details below summarize the linked sources.</p>`:''}<div class="detail-technical-grid">${cards.map(([key,label,fallback])=>`<section class="detail-technical-card"><h4>${h(label)}</h4>${detailList(details[key],fallback)}</section>`).join('')}</div></section>${details.detection.length?`<section class="detail-section detail-triage"><h3>${icon('search')} Detection & triage <span class="detail-section-label">ANALYST CHECKLIST</span></h3><p class="detail-caption">Review steps informed by the source. These are investigation leads, not confirmed indicators of compromise.</p>${detailList(details.detection,'')}</section>`:''}${details.limitations.length?`<section class="detail-section"><div class="detail-limitations"><h4>${icon('info')} What remains unconfirmed</h4>${detailList(details.limitations,'')}</div></section>`:''}`;
}
function detailCves(event) {
  const cves=event.cves.filter(cve=>cveURL(cve));
  if(!cves.length)return `<section class="detail-section"><h3>${icon('layers')} Vulnerability references</h3><p class="detail-unavailable">No validated CVE identifier is associated with this record. Incidents and news stories may not have a public CVE.</p></section>`;
  return `<section class="detail-section"><h3>${icon('layers')} ${isNewsEvent(event)?'CVEs mentioned in the publication':'Vulnerability references'}</h3><div class="cve-tags">${cves.slice(0,16).map(cve=>`<a class="cve-tag detail-cve-link" href="${h(cveURL(cve))}" target="_blank" rel="noopener noreferrer" aria-label="${h(cve)} — open official CVE record">${h(cve)} ${icon('external')}</a>`).join('')}</div><p class="detail-caption">Opens the official CVE record. Some identifiers may be reserved or awaiting public details.${cves.length>16?` Showing 16 of ${cves.length}; the copied brief includes all identifiers.`:''}</p></section>`;
}
function detailRelated(event) {
  const related=relatedEvents(event,state.data.events);
  return `<section class="detail-section"><h3>${icon('link')} Related records <span class="detail-section-label">${related.length} IN SNAPSHOT</span></h3>${related.length?`<div class="detail-related-list">${related.map(item=>`<button class="detail-related-record" data-open-event="${h(item.event.id)}"><span><span class="detail-relation">${h(item.reason)}</span><strong>${h(item.event.title)}</strong><span class="detail-related-meta">${h(item.event.category)} · ${h(fullDate(item.event.publishedAt))}</span></span>${icon('arrow')}</button>`).join('')}</div><p class="detail-caption">A shared CVE or organization provides context; it does not establish that reports describe the same incident.</p>`:'<p class="detail-unavailable">No other records in this snapshot share a validated CVE or a specific affected organization.</p>'}</section>`;
}
function detailCoverage(event) {
  if(event.bangladeshScope!=='coverage')return '';
  const channel=state.data.sources.find(source=>source.id===event.sourceId);
  const headlineMatch=channel?.group==='bangladesh' && channel?.kind==='secondary' && /\bcyber/i.test(event.title);
  return `<section class="detail-section"><div class="detail-coverage-note"><h4>${icon('globe')} Bangladesh publication context</h4><p>${headlineMatch?'This Bangladesh publisher’s headline contains “cyber” and matches the local newspaper topic filter.':'This article is classified as Bangladesh news coverage.'} Publisher location does not establish that an incident occurred in Bangladesh or affected Bangladeshi victims. Read the original story for the reported incident location and attribution.</p></div></section>`;
}
function renderDetail() {
  const event=state.data?.events.find(item=>item.id===state.selectedId);
  if(!event)return;
  const news=isNewsEvent(event);
  const channel=state.data.sources.find(source=>source.id===event.sourceId);
  const primaryCount=event.sources.filter(source=>source.kind==='primary').length;
  $('#detail-header').innerHTML=`<div class="detail-heading"><div class="detail-labels">${eventBadge(event)}<span class="detail-category">${h(news?'Publisher update':event.category)}</span>${event.bangladeshScope?`<span class="detail-category">${h(scopeLabels[event.bangladeshScope])}</span>`:''}${event.exploited?'<span class="detail-category">Exploitation reported</span>':''}</div><h2 id="detail-title">${h(event.title)}</h2><div class="detail-org-line"><span class="org-icon" aria-hidden="true">${h(initials(event.organization))}</span><span>${h(event.organization)}</span><span class="meta-sep"></span><span class="detail-date">Published ${h(fullDate(event.publishedAt))}</span></div></div>`;
  const saved=state.saved.has(event.id);
  $('#detail-bookmark').classList.toggle('saved',saved);
  $('#detail-bookmark').setAttribute('aria-label',saved?'Remove event from watchlist':'Save event to watchlist');
  $('#detail-bookmark').setAttribute('aria-pressed',String(saved));
  $('#detail-footer-note').textContent=`Record updated ${fullDate(event.updatedAt)} · ${event.sources.length} source${event.sources.length===1?'':'s'}`;
  $$('.detail-tabs [data-detail-tab]').forEach(button=>{const active=button.dataset.detailTab===state.detailTab;button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;});
  $('#detail-panel').setAttribute('aria-labelledby',`detail-tab-${state.detailTab}`);
  if(state.detailTab==='timeline') {
    const timeline=event.timeline.length?event.timeline:[{date:event.publishedAt,title:'Source published',description:event.summary}];
    $('#detail-panel').innerHTML=`<section class="detail-section"><h3>${icon('clock')} ${news?'Publication history':'Event timeline'}</h3><p>Source-reported milestones. A date without a time retains the publisher’s date; exact timestamps are shown in Bangladesh time (BDT).</p></section><ol class="timeline">${timeline.map(item=>`<li><time datetime="${h(item.date)}">${h(detailDate(item.date))}</time><h3>${h(item.title)}</h3><p>${h(item.description)}</p></li>`).join('')}</ol>${detailProvenance(event)}`;
  } else if(state.detailTab==='evidence') {
    $('#detail-panel').innerHTML=`<section class="detail-section"><h3>${icon('shield')} Evidence assessment</h3><div class="assessment-note"><strong>${event.confidence==='confirmed'?'CONFIRMED SOURCE REPORT':'REPORTED · SEE QUALIFICATIONS'}</strong>${h(event.evidenceNote||'Read the original source for the scope and confidence of this report.')}</div><p class="detail-caption">${primaryCount} primary source${primaryCount===1?'':'s'} · ${event.sources.length-primaryCount} secondary report${event.sources.length-primaryCount===1?'':'s'}. Confidence describes the source report; it does not independently confirm every technical claim.</p></section>${detailCoverage(event)}<section class="detail-section"><h3>${icon('link')} Original sources</h3>${event.sources.length?event.sources.map(source=>`<a class="evidence-source" href="${h(safeURL(source.url))}" target="_blank" rel="noopener noreferrer"><span class="evidence-source-header"><strong>${h(source.name)}</strong>${icon('external')}</span><span class="source-kind">${source.kind==='primary'?'PRIMARY SOURCE':'SECONDARY REPORT'}${source.publishedAt?' · '+h(detailDate(source.publishedAt)):''}</span><span class="source-url">${h(source.url)}</span></a>`).join(''):'<p>No source links are included in this record.</p>'}</section>${detailCves(event)}${detailProvenance(event)}<div class="assessment-note"><strong>READ BEFORE ACTING</strong>Recommendations are source-informed analyst guidance. Confirm affected versions, configurations and business exposure against the linked original advisory. Missing indicators, scores or attack details have not been inferred.</div>`;
  } else if(news) {
    const original=event.sources.find(source=>safeURL(source.url));
    $('#detail-panel').innerHTML=`<dl class="context-grid"><div><dt>PUBLISHER</dt><dd>${h(channel?.name||event.organization)}</dd></div><div><dt>PUBLICATION TYPE</dt><dd>News, research or release note</dd></div><div><dt>${event.bangladeshScope==='coverage'?'COVERAGE / PUBLISHER REGION':'REGION / REACH'}</dt><dd>${h(event.geography.join(', ')||'Not specified')}</dd></div><div><dt>ASSESSMENT</dt><dd>Publisher update · unscored</dd></div></dl><section class="detail-section"><h3>${icon('newspaper')} Publisher brief</h3><p>${h(event.description||event.summary)}</p>${original?`<a class="button primary original-article" href="${h(safeURL(original.url))}" target="_blank" rel="noopener noreferrer">Read original publication ${icon('external')}</a>`:''}</section>${detailCoverage(event)}<section class="detail-section"><h3>${icon('alert')} Reported impact & relevance</h3>${detailList(event.impact,'Impact is not established in the available publication metadata.')}</section><section class="detail-section"><h3>${icon('shield')} Review & follow-up</h3><p class="detail-caption">Analyst guidance for reviewing this publication.</p>${detailList(event.recommendations,'Read the original report and verify any affected products or organizations before taking action.',true)}</section>${event.technicalDetails?detailTechnical(event):''}${event.evidenceNote?`<section class="detail-section"><div class="assessment-note"><strong>PUBLICATION EVIDENCE & LIMITS</strong>${h(event.evidenceNote)}</div></section>`:''}${detailCves(event)}${detailProvenance(event)}${detailRelated(event)}<div class="assessment-note"><strong>READ IN CONTEXT</strong>This is a publisher update. Inclusion does not assign a severity or establish compromise of an organization. Feed excerpts may omit technical context; verify claims in the original publication.</div>`;
  } else {
    $('#detail-panel').innerHTML=`<dl class="context-grid"><div><dt>REPORTED STATUS</dt><dd>${h(event.status)}</dd></div><div><dt>EVIDENCE</dt><dd>${event.confidence==='confirmed'?'Confirmed source report':'Reported · qualified'}</dd></div><div><dt>REGION / REACH</dt><dd>${h(event.geography.join(', ')||'Not specified')}</dd></div><div><dt>SECTOR / TECHNOLOGY</dt><dd>${h(event.sectors.join(', ')||'Not specified')}</dd></div></dl><section class="detail-section"><h3>${icon('file')} What happened</h3><p>${h(event.description||event.summary)}</p></section><section class="detail-section"><div class="assessment-note"><strong>SEVERITY & EXPLOITATION</strong>${h(event.severityBasis)}<span class="detail-assessment-extra">${event.exploited?'Exploitation is reported in the source material.':'Vulnerability exploitation is not established by this record. This flag does not determine whether a reported breach occurred.'}</span></div></section>${detailTechnical(event)}<section class="detail-section"><h3>${icon('alert')} Potential impact</h3>${detailList(event.impact,'Impact has not been established. Review the source before determining exposure.')}</section><section class="detail-section"><h3>${icon('shield')} Recommended actions</h3>${detailList(event.recommendations,'Review the original advisory and assess applicability to your environment.',true)}</section>${detailCves(event)}${event.evidenceNote?`<section class="detail-section"><div class="assessment-note"><strong>EVIDENCE NOTE</strong>${h(event.evidenceNote)}</div></section>`:''}${detailProvenance(event)}${detailRelated(event)}${event.tags.length?`<div class="tag-list">${event.tags.map(tag=>`<span class="tag">${h(tag)}</span>`).join('')}</div>`:''}`;
  }
}
function setDetailTab(tab) {
  const previousScroll=$('#detail-scroll').scrollTop;
  state.detailTab=tab;renderDetail();
  $('#detail-scroll').scrollTop=Math.min(previousScroll,$('#detail-header').offsetHeight);
}
function openEvent(id,{updateHash=true}={}) {
  if(!state.data?.events.some(event=>event.id===id)){toast('This event is not in the current snapshot.');return;}
  state.selectedId=id;state.detailTab='overview';renderDetail();
  if(!$('#event-dialog').open)$('#event-dialog').showModal();
  $('#detail-scroll').scrollTop=0;
  document.body.classList.add('overflow-clip');
  if(updateHash)history.replaceState(null,'',`#event=${encodeURIComponent(id)}`);
  $('#detail-close').focus();
}
function closeEvent() { $('#event-dialog').close(); }
$('#event-dialog').addEventListener('close',()=>{const closedId=state.selectedId;state.selectedId=null;document.body.classList.remove('overflow-clip');history.replaceState(null,'',`#${state.view}`);const row=$$('[data-open-event]').find(button=>button.dataset.openEvent===closedId);(row||$('.nav-item[aria-current="page"]')||$('#search-input')).focus();});
function toggleBookmark() {
  const id=state.selectedId;if(!id)return;
  if(state.saved.has(id))state.saved.delete(id);else state.saved.add(id);
  try{localStorage.setItem(STORAGE_KEY,JSON.stringify([...state.saved]));storageAvailable=true;}catch{storageAvailable=false;}
  renderDetail();render();
  toast(storageAvailable?(state.saved.has(id)?'Event saved to your watchlist.':'Event removed from your watchlist.'):'Watchlist changed for this session. Browser storage is unavailable.');
}
async function copyBrief() {
  const event=state.data?.events.find(item=>item.id===state.selectedId);if(!event)return;
  const brief=makeBrief(event,state.data.sources.find(source=>source.id===event.sourceId));
  try { await navigator.clipboard.writeText(brief);toast('Incident brief copied, including source links.'); }
  catch {
    const textarea=document.createElement('textarea');textarea.value=brief;textarea.setAttribute('aria-label','Incident brief to copy');$('#detail-panel').appendChild(textarea);textarea.select();
    try {if(!document.execCommand('copy'))throw new Error('Copy unavailable');textarea.remove();toast('Incident brief copied.');}
    catch{toast('Automatic copy is unavailable. The brief is selected in the detail panel; press Ctrl+C.');}
  }
}
function exportCSV() {
  const events=visibleEvents();if(!events.length){toast('No events to export.');return;}
  const url=URL.createObjectURL(new Blob([makeCSV(events)],{type:'text/csv;charset=utf-8'}));
  const link=document.createElement('a');link.href=url;link.download=`cyberwatch-${state.view}-${new Date().toISOString().slice(0,10)}.csv`;document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  toast(`Exported ${events.length} event${events.length===1?'':'s'} with impact, recommendations, and sources.`);
}

function renderRefreshControls() {
  const button=$('#refresh-button');
  const busy=state.initializing||state.loading||state.collecting;
  button.disabled=busy;
  $$('[data-retry]').forEach(retry=>{retry.disabled=busy;});
  button.classList.toggle('refreshing',busy);
  button.setAttribute('aria-busy',String(busy));
  const label=state.initializing?'Connecting…':state.collecting?'Checking feeds…':state.loading?'Loading…':feedClient?.supportsLive?'Refresh':'Reload snapshot';
  button.innerHTML=`<span>${icon('refresh')}</span>${label}`;
  button.title=feedClient?.supportsLive?'Check the configured publishers now and load the results':'Load the latest snapshot published by the scheduled workflow';
  const note=$('#refresh-note');
  const ready=feedClient?.supportsLive
    ? 'Automatic checks every 30 minutes · Refresh checks publishers now.'
    : 'Published snapshot · checks scheduled every 30 minutes. Connect the live service for on-demand checks.';
  const unavailable=feedClient?.discoveryError && feedClient.discoveryError.status!==404;
  note.textContent=state.initializing?'Connecting to the feed service…':state.collectionMessage||state.configurationWarning||(unavailable?'Live service unavailable. Showing the published snapshot; reload to retry the connection.':ready);
  note.classList.toggle('freshness-warning',state.collectionWarning||Boolean(state.configurationWarning)||Boolean(unavailable&&!feedClient?.supportsLive));
}

async function initializeFeed() {
  state.initializing=true;
  renderRefreshControls();
  let apiBase='auto';
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),10000);
  try {
    const response=await fetch(new URL('./config.json',import.meta.url),{cache:'no-store',credentials:'same-origin',signal:controller.signal,redirect:'error'});
    if(!response.ok)throw new Error('Configuration unavailable');
    const body=await response.text();
    if(body.length>16000)throw new Error('Configuration too large');
    const config=JSON.parse(body);
    if(typeof config.apiBase!=='string')throw new Error('Invalid service URL');
    apiBase=config.apiBase;
    feedClient=createFeedClient({baseURL:new URL('./',import.meta.url),apiBase,refreshTimeoutMs:210000});
  } catch {
    state.configurationWarning='Live service configuration could not be read. Using same-origin discovery; check dist/config.json.';
    feedClient=createFeedClient({baseURL:new URL('./',import.meta.url),refreshTimeoutMs:210000});
  } finally {clearTimeout(timer);}
  await feedClient.discover();
  state.initializing=false;
  await loadSnapshot();
}

async function loadSnapshot({manual=false}={}) {
  if(state.loading||!feedClient)return false;
  state.loading=true;state.browserAttemptAt=new Date().toISOString();
  renderRefreshControls();
  try {
    const data=normalizeData(await feedClient.snapshot());
    const oldGeneratedAt=state.data?.generatedAt,oldDatabaseAt=state.data?.databaseUpdatedAt;
    const changed=JSON.stringify(data)!==JSON.stringify(state.data);
    state.data=data;
    state.browserCheckedAt=new Date().toISOString();state.refreshFailed=false;
    const errors=data.sources.filter(source=>source.status==='error').length;
    const age=data.lastCheckedAt?Date.now()-Date.parse(data.lastCheckedAt):Infinity;
    const status=$('#load-status');status.classList.remove('error');
    if(errors){status.hidden=false;status.textContent=`${errors} source channel${errors===1?'':'s'} could not be collected. Last available records are retained where possible. Open Sources for details.`;}
    else if(age>90*60*1000){
      status.hidden=false;
      const action=feedClient.supportsLive?'Press Refresh to check the publishers now.':'Check the scheduled GitHub workflow or connect the live service.';
      status.textContent=(data.lastCheckedAt?`The last feed check was ${fullTimestamp(data.lastCheckedAt)}. `:'No feed-check timestamp is recorded. ')+action;
    } else {status.hidden=true;status.textContent='';}
    if(changed){
      const active=document.activeElement;
      const focusEvent=active?.dataset.openEvent,focusSource=active?.dataset.sourceFilter;
      const focusDetail=active?.dataset.detailTab;
      const detailScroll=$('#detail-scroll').scrollTop;
      render();
      if(state.selectedId){
        if(data.events.some(event=>event.id===state.selectedId)){renderDetail();$('#detail-scroll').scrollTop=detailScroll;}
        else closeEvent();
      }
      if(focusEvent)$$('[data-open-event]').find(el=>el.dataset.openEvent===focusEvent)?.focus({preventScroll:true});
      else if(focusSource)$$('[data-source-filter]').find(el=>el.dataset.sourceFilter===focusSource)?.focus({preventScroll:true});
      else if(focusDetail)$$('[data-detail-tab]').find(el=>el.dataset.detailTab===focusDetail)?.focus({preventScroll:true});
    }
    if(manual)toast(oldDatabaseAt===data.databaseUpdatedAt?'Published snapshot reloaded. No new record changes.':`Snapshot changes loaded. Last feed check: ${fullTimestamp(data.lastCheckedAt)}.`);
    if(!oldGeneratedAt)routeHash();
    return true;
  } catch(error) {
    state.refreshFailed=true;
    const status=$('#load-status');status.hidden=false;status.classList.add('error');
    status.textContent=state.data?'Could not load the latest snapshot. Your last loaded data remains available. Try again shortly.':'Could not load the intelligence snapshot. Check the feed service or published data/incidents.json file, then try again.';
    if(!state.data){$('#event-list').innerHTML=`<div class="empty-state"><span>${icon('radio')}</span><h3>The feed could not be loaded.</h3><p>${h(error.message)}</p><button class="button secondary" data-retry>Try again ${icon('refresh')}</button></div>`;$('#event-list').setAttribute('aria-busy','false');$('#result-count').textContent='OFFLINE';$('#console-footer-text').textContent='Source snapshot unavailable';}
    if(manual)toast('Snapshot reload failed. See the message above the feed.');
    return false;
  } finally {state.loading=false;renderFreshness();renderRefreshControls();}
}

async function manualRefresh() {
  if(state.initializing||state.loading||state.collecting)return;
  state.collectionMessage='';state.collectionWarning=false;
  state.collectionNoticeUntil=0;
  if(!feedClient.supportsLive){
    state.initializing=true;renderRefreshControls();
    await feedClient.discover();
    state.initializing=false;
    if(!feedClient.supportsLive){await loadSnapshot({manual:true});return;}
  }
  const previousDatabaseAt=state.data?.databaseUpdatedAt;
  state.collecting=true;
  state.collectionMessage='Starting a fresh publisher check…';
  renderRefreshControls();
  try {
    const result=await feedClient.refresh({onStatus:status=>{
      if(status.refresh.status==='running'){
        state.collectionMessage=status.coalesced?'A publisher check is already running. Waiting for its results…':'Checking the configured publishers now. Results will appear when the collection finishes…';
        renderRefreshControls();
      }
    }});
    const loaded=await loadSnapshot();
    state.collectionWarning=result.refresh.status==='partial'||!loaded;
    if(!loaded)state.collectionMessage='The publisher check finished, but the new snapshot could not be loaded. Your previous data is still available.';
    else if(result.refresh.status==='partial')state.collectionMessage='Publisher check completed with source errors. Available updates loaded; previous records retained where possible. See Sources for details.';
    else state.collectionMessage=previousDatabaseAt===state.data.databaseUpdatedAt?'Publishers checked successfully. No new record changes. Automatic checks continue every 30 minutes.':'Fresh publisher updates loaded. Automatic checks continue every 30 minutes.';
    toast(state.collectionMessage);
  } catch(error) {
    state.collectionWarning=true;
    if(error.code==='cooldown'){
      state.collectionNoticeUntil=Date.now()+error.retryAfter*1000;
      state.collectionMessage=`A check was just requested. You can start another after ${fullTimestamp(new Date(state.collectionNoticeUntil).toISOString())}. Loading the latest available snapshot.`;
      await loadSnapshot();
    } else if(['refresh_timeout','request_timeout','network_error','aborted'].includes(error.code)){
      state.collectionMessage='The live check could not be confirmed. It may still finish on the server; the dashboard will retry loading results automatically.';
    } else if(error.code==='collection_failed'){
      state.collectionMessage=error.message;
      await loadSnapshot();
    } else state.collectionMessage=error.message;
    toast(state.collectionMessage);
  } finally {state.collecting=false;if(!state.collectionNoticeUntil)state.collectionNoticeUntil=Date.now()+60000;renderRefreshControls();}
}

async function pollSnapshot() {
  if(document.hidden||state.initializing||state.loading||state.collecting)return;
  const previousCheck=state.data?.lastCheckedAt;
  if(await loadSnapshot()){
    if(state.data.lastCheckedAt!==previousCheck||Date.now()>=state.collectionNoticeUntil){
      state.collectionMessage='';state.collectionWarning=false;renderRefreshControls();
    }
  }
}

function routeHash() {
  const hash=location.hash.slice(1);
  if(hash==='main-content')return;
  if(hash.startsWith('event=')){
    let id;try{id=decodeURIComponent(hash.slice(6));}catch{return;}
    const record=state.data?.events.find(event=>event.id===id);
    if(record)setView(isBangladeshEvent(record)?'bangladesh':isNewsEvent(record)?'newsletters':'feed',{reset:true,updateHash:false});
    openEvent(id,{updateHash:false});
  }else{
    if($('#event-dialog').open)$('#event-dialog').close();
    setView(hash||'feed',{reset:state.view!==(hash||'feed'),updateHash:false});
  }
}
document.addEventListener('click',event=>{
  const target=event.target.closest('button,a');if(!target)return;
  if(target.dataset.view){setView(target.dataset.view,{reset:true});window.scrollTo({top:0,behavior:'instant'});$('#page-title').focus({preventScroll:true});return;}
  if(target.dataset.openEvent){openEvent(target.dataset.openEvent);return;}
  if(target.dataset.collection){setView('feed',{reset:true});state.category=target.dataset.collection;renderEventList();return;}
  if(target.dataset.sourceFilter){const source=state.data?.sources.find(item=>item.id===target.dataset.sourceFilter);const view=['newsletters','bangladesh'].includes(state.view)?state.view:source?.group==='news'?'newsletters':source?.group==='bangladesh'?'bangladesh':'feed';const selected=state.source===target.dataset.sourceFilter;setView(view,{reset:true});state.source=selected?'all':target.dataset.sourceFilter;renderEventList();return;}
  if(target.dataset.regionScope){state.regionScope=target.dataset.regionScope;state.tab='all';state.limit=12;renderEventList();return;}
  if(target.dataset.feedTab){state.tab=target.dataset.feedTab;state.limit=12;renderEventList();return;}
  if(target.dataset.detailTab){setDetailTab(target.dataset.detailTab);return;}
  if(target.dataset.emptyAction==='feed'){setView('feed',{reset:true});return;}
  if(target.dataset.emptyAction==='reset'){resetFilters();return;}
  if(target.hasAttribute('data-retry')&&!state.initializing&&!state.collecting)loadSnapshot({manual:true});
});
$('#search-input').addEventListener('input',event=>{state.query=event.target.value;state.limit=12;renderEventList();});
$('#severity-filter').addEventListener('change',event=>{state.severity=event.target.value;state.limit=12;renderEventList();});
$('#period-filter').addEventListener('change',event=>{state.period=event.target.value;state.limit=12;renderEventList();});
$('#publisher-filter').addEventListener('change',event=>{state.source=event.target.value;state.limit=12;renderEventList();});
$('#sort-select').addEventListener('change',event=>{state.sort=event.target.value;state.limit=12;renderEventList();});
$('#reset-filters').addEventListener('click',()=>{resetFilters();toast('All filters cleared.');});
$('#load-more').addEventListener('click',()=>{const current=state.limit;state.limit+=12;renderEventList();const rows=state.view==='newsletters'?$$('.newsletter-card h3 button'):$$('.event-row');rows[current]?.focus();});
$('#refresh-button').addEventListener('click',manualRefresh);
$('#export-button').addEventListener('click',exportCSV);
$('#detail-close').addEventListener('click',closeEvent);
$('#detail-bookmark').addEventListener('click',toggleBookmark);
$('#copy-brief').addEventListener('click',copyBrief);
$('#event-dialog').addEventListener('click',event=>{if(event.target===$('#event-dialog')){const r=$('#event-dialog').getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)closeEvent();}});
const showInfo=()=>{$('#info-dialog').showModal();document.body.classList.add('overflow-clip');};
$('#methodology-open').addEventListener('click',showInfo);
$('#shortcuts-open').addEventListener('click',showInfo);
$('#info-close').addEventListener('click',()=>$('#info-dialog').close());
$('#info-done').addEventListener('click',()=>$('#info-dialog').close());
$('#info-dialog').addEventListener('close',()=>{if(!$('#event-dialog').open)document.body.classList.remove('overflow-clip');});
document.addEventListener('keydown',event=>{
  const typing=['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)||document.activeElement?.isContentEditable;
  if(event.key==='/'&&!typing&&!$('#event-dialog').open&&!$('#info-dialog').open){event.preventDefault();if(state.view==='sources')setView('feed');$('#search-input').focus();}
  if(event.target.matches('.detail-tabs [data-detail-tab]')&&['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){
    event.preventDefault();const tabs=$$('.detail-tabs [data-detail-tab]');const index=tabs.indexOf(event.target);const next=event.key==='Home'?0:event.key==='End'?tabs.length-1:(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;
    setDetailTab(tabs[next].dataset.detailTab);tabs[next].focus({preventScroll:true});
  }
});
window.addEventListener('hashchange',routeHash);
window.addEventListener('storage',event=>{if(event.key===STORAGE_KEY){try{const ids=JSON.parse(event.newValue||'[]');if(Array.isArray(ids)){state.saved=new Set(ids.filter(id=>typeof id==='string'&&id.length<=180).slice(0,500));render();if(state.selectedId)renderDetail();}}catch{/* Retain existing state if another tab writes invalid data. */}}});
initializeFeed();
setInterval(pollSnapshot,60000);
document.addEventListener('visibilitychange',()=>{
  if(!document.hidden && (!state.browserCheckedAt||Date.now()-Date.parse(state.browserCheckedAt)>60000))pollSnapshot();
});
