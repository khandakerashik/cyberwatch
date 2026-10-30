import { escapeHTML as h, safeURL } from './core.js';
import { SOURCE_GROUP_LABELS, QUALITY_LABELS, sourceQualityRows, filterQualityRows, qualitySummary, makeQualityCSV, historyItems, calendarDate, monthCalendar, shiftMonth } from './insights-core.js';

const timestamp=value=>value?new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Dhaka',day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).format(new Date(value))+' BDT':'Not recorded';
const dateLabel=value=>value?new Intl.DateTimeFormat('en-GB',{timeZone:'UTC',day:'numeric',month:'long',year:'numeric'}).format(new Date(value+'T12:00:00Z')):'No date';
const monthLabel=value=>new Intl.DateTimeFormat('en-GB',{timeZone:'UTC',month:'long',year:'numeric'}).format(new Date(value+'-01T12:00:00Z'));
const option=(value,label)=>`<option value="${h(value)}">${h(label)}</option>`;
const number=value=>new Intl.NumberFormat('en-GB').format(value);
const metric=(label,value,note)=>`<article class="quality-metric"><small>${h(label)}</small><strong>${h(value)}</strong><p>${h(note)}</p></article>`;

export function createSourceQuality({getData,onResults=()=>{}}) {
  const root=()=>document.querySelector('#quality-view');
  const filters={query:'',status:'all',group:'all',sort:'attention'};
  const expanded=new Set();let mounted=false;
  const rows=()=>sourceQualityRows(getData());
  const filtered=()=>filterQualityRows(rows(),filters);
  function mount() {
    if(mounted)return;
    root().innerHTML=`<div class="quality-page"><section class="quality-intro"><span class="eyebrow">COLLECTION HEALTH & READING COVERAGE</span><p>See which channels are working, when they were checked, and how much source text is available in this snapshot.</p><details class="quality-methodology"><summary>How these measures work</summary><p>Health describes collection, not publisher accuracy. A check is overdue after two hours without a recorded attempt; this is four expected 30-minute intervals. Success rates use up to 48 actual recorded checks per source, with the sample count shown. Missing runs are not counted as successes or failures. A successful source can legitimately contain no matching records.</p><p>Reader coverage is calculated from retained records. Full text is shown only where the configured source policy permits it and the available text passes completeness checks. A source link or reviewed context is not a full publisher article. These figures do not measure worldwide coverage, editorial credibility, or independent verification.</p></details></section><div id="quality-metrics" class="quality-metrics"></div><div class="quality-toolbar"><label>Find a source<input id="quality-search" type="search" maxlength="200" placeholder="Publisher, project, error…" autocomplete="off"></label><label>Collection state<select id="quality-status">${option('all','All states')}${option('attention','Needs attention')}${Object.entries(QUALITY_LABELS).map(([id,label])=>option(id,label)).join('')}</select></label><label>Collection<select id="quality-group">${option('all','All collections')}${Object.entries(SOURCE_GROUP_LABELS).map(([id,label])=>option(id,label)).join('')}</select></label><label>Sort by<select id="quality-sort">${option('attention','Needs attention first')}${option('name','Source name')}${option('records','Most records')}${option('coverage','Full text coverage')}</select></label></div><p id="quality-caption" class="quality-results-caption" role="status" aria-live="polite"></p><div class="quality-table-wrap"><table class="quality-table"><caption class="sr-only">Source collection health and reader availability</caption><thead><tr><th scope="col">Source</th><th scope="col">Collection</th><th scope="col">Recent checks</th><th scope="col">Records</th><th scope="col">Reader coverage</th><th scope="col">Inspect</th></tr></thead><tbody id="quality-rows"></tbody></table></div><div class="quality-legend"><span><i data-reader="full"></i>Full text</span><span><i data-reader="excerpt"></i>Excerpt</span><span><i data-reader="restricted"></i>Publisher access</span><span><i data-reader="unavailable"></i>Source / context only</span></div><p class="quality-notice">History is retained in the collected snapshot. This upgrade starts with the previous recorded attempt, where available; additional checks build the history. Restoring a snapshot also restores its recorded history.</p></div>`;
    root().addEventListener('input',event=>{if(event.target.id==='quality-search'){filters.query=event.target.value;renderRows();}});
    root().addEventListener('change',event=>{for(const key of ['status','group','sort'])if(event.target.id===`quality-${key}`){filters[key]=event.target.value;renderRows();}});
    root().addEventListener('click',event=>{
      const button=event.target.closest('[data-quality-toggle]');if(!button)return;
      const id=button.dataset.qualityToggle;if(expanded.has(id))expanded.delete(id);else expanded.add(id);
      renderRows();root().querySelector(`[data-quality-toggle="${CSS.escape(id)}"]`)?.focus({preventScroll:true});
    });mounted=true;
  }
  function renderRows() {
    const items=filtered();
    root().querySelector('#quality-caption').textContent=`${items.length} of ${getData()?.sources.length||0} channels · latest collection ${timestamp(getData()?.lastCheckedAt)}`;
    root().querySelector('#quality-rows').innerHTML=items.length?items.map(row=>{
      const coverageText=`${row.coverage.full} full · ${row.coverage.excerpt} excerpt · ${row.coverage.restricted} restricted · ${row.coverage.unavailable} source/context`;
      const expandedId=`quality-detail-${row.id}`;
      return `<tr><td data-label="Source"><strong class="quality-source-name">${h(row.name)}</strong><span class="quality-source-meta">${h(SOURCE_GROUP_LABELS[row.group]||row.group)} · ${row.kind==='curated'?'Reviewed records':row.kind==='secondary'?'Secondary reporting':'Primary publisher'}</span></td><td data-label="Collection"><span class="quality-status-badge" data-status="${h(row.status)}">${h(QUALITY_LABELS[row.status])}</span><small>${row.manual?'Editorial maintenance':row.lastAttemptAt?timestamp(row.lastAttemptAt):'No automated attempt recorded'}</small>${row.overdue&&row.status==='error'?'<small>Check also overdue</small>':''}</td><td data-label="Recent checks">${row.manual?'<span>Not automated</span>':row.checks.length?`<strong>${row.successRate}%</strong><small>${row.successes}/${row.checks.length} recorded checks succeeded</small><div class="quality-checks" role="img" aria-label="${row.successes} of ${row.checks.length} recorded checks succeeded, oldest to newest">${row.checks.map(check=>`<span data-status="${h(check.status)}" title="${h(timestamp(check.at))} · ${check.status==='ok'?'Succeeded':'Failed'} · ${check.recordCount} displayed records"></span>`).join('')}</div>`:'<span>No history yet</span>'}</td><td data-label="Records"><strong>${number(row.recordCount)}</strong><small>${row.recordCount?`Newest ${h(dateLabel(calendarDate(row.newestPublication)))}`:row.group==='research'&&row.id.startsWith('watch-')?'Edition monitor':'No retained items'}</small></td><td data-label="Reader coverage"><strong>${row.coverage.full} full / ${row.recordCount}</strong><div class="quality-coverage-bar" role="img" aria-label="${h(coverageText)}">${Object.entries(row.coverage).map(([status,count])=>count?`<span data-reader="${h(status)}" data-percent="${count/row.recordCount*100}" title="${h(status)}: ${count}"></span>`:'').join('')}</div><small>${row.coverage.excerpt} excerpts · ${row.coverage.restricted} restricted</small></td><td data-label="Inspect"><button class="button subtle" data-quality-toggle="${h(row.id)}" aria-expanded="${expanded.has(row.id)}" aria-controls="${h(expandedId)}">${expanded.has(row.id)?'Hide details':'Details'}</button></td></tr><tr class="quality-detail-row" ${expanded.has(row.id)?'':'hidden'}><td colspan="6"><section id="${h(expandedId)}" class="quality-source-detail" aria-label="${h(row.name)} collection details"><dl class="quality-detail-grid"><div><dt>Last successful check</dt><dd>${h(timestamp(row.lastSuccessAt))}</dd></div><div><dt>Recorded history begins</dt><dd>${h(timestamp(row.checks[0]?.at))}</dd></div><div><dt>Reader availability</dt><dd>${h(coverageText)}</dd></div><div><dt>Latest collection outcome</dt><dd>${h(row.error||(row.manual?'Maintained as reviewed source context.':row.status==='ok'?'Last attempt succeeded.':row.overdue?'Last known result retained; check the publishing workflow.':'No automated outcome recorded.'))}</dd></div></dl><p>${h(row.description||'Source metadata and original links are preserved with each record.')}</p><div class="quality-detail-actions"><button class="button subtle" data-source-filter="${h(row.id)}">Browse records</button>${safeURL(row.url)?`<a class="button subtle" href="${h(safeURL(row.url))}" target="_blank" rel="noopener noreferrer">Open source <span aria-hidden="true">↗</span></a>`:''}</div></section></td></tr>`;
    }).join(''):'<tr><td colspan="6"><div class="history-empty">No sources match these filters.</div></td></tr>';
    // CSSOM preserves the strict style-src policy; no inline HTML styles.
    root().querySelectorAll('.quality-coverage-bar [data-percent]').forEach(bar=>{bar.style.width=`${Number(bar.dataset.percent)||0}%`;});
    onResults(items.length);
  }
  function render() {
    mount();const summary=qualitySummary(rows());
    root().querySelector('#quality-metrics').innerHTML=metric('HEALTHY CHANNELS',`${summary.healthy} / ${summary.automatic}`,`${summary.total-summary.automatic} curated channels listed separately`)+metric('NEEDS ATTENTION',String(summary.errors+rows().filter(row=>['stale','unknown'].includes(row.status)).length),`${summary.errors} fetch errors · ${summary.overdue} overdue checks`)+metric('RECORDED SUCCESS RATE',summary.samples?`${Math.round(summary.successes/summary.samples*100)}%`:'—',`${summary.successes} successes across ${summary.samples} recorded checks`)+metric('FULL TEXT IN READER',number(summary.full),`${summary.records} records in this snapshot; excerpts shown separately`);
    renderRows();
  }
  return {render,reset:()=>{Object.assign(filters,{query:'',status:'all',group:'all',sort:'attention'});if(mounted){root().querySelector('#quality-search').value='';for(const key of ['status','group','sort'])root().querySelector(`#quality-${key}`).value=filters[key];}},csv:()=>makeQualityCSV(filtered()),count:()=>filtered().length,focusSearch:()=>{mount();root().querySelector('#quality-search').focus();}};
}

export function createIncidentHistory({getData,onResults=()=>{}}) {
  const root=()=>document.querySelector('#history-view');
  const filters={query:'',basis:'milestones',scope:'major',category:'all'};
  let mounted=false,month='',selectedDay='',limit=36;
  const items=()=>historyItems(getData(),filters);
  const currentItems=()=>items().filter(item=>item.day.startsWith(month)&&(!selectedDay||item.day===selectedDay));
  function mount() {
    if(mounted)return;
    root().innerHTML=`<div class="history-page"><section class="history-intro"><span class="eyebrow">WHAT HAPPENED, AND WHEN</span><p>Explore reported milestones from reviewed incident timelines, or switch to publication dates for the wider cybersecurity stream.</p><details><summary>Dates, importance and coverage</summary><p>Reported milestones use explicit dates already documented in reviewed records. Publication dates show when a source published a report or an entry was added to a catalog; they are not assumed to be the attack date. “Major” includes incident records, critical/high assessments and reported exploitation. It does not rank unscored news headlines. Choose all cybersecurity records in the publication view to see broader reporting.</p><p>Dates with a time are displayed in Bangladesh time (UTC+06:00). Date-only source values retain their calendar date. Reviewed records remain available; automated publications follow source retention limits. This is a history of the records collected by CyberWatch, not an exhaustive worldwide incident archive.</p></details></section><div class="history-toolbar"><label>Search history<input id="history-search" type="search" maxlength="200" placeholder="Incident, organization, CVE…" autocomplete="off"></label><label>Date basis<select id="history-basis">${option('milestones','Reported milestones')}${option('publications','Publication dates')}</select></label><label>Show<select id="history-scope">${option('major','Major events')}${option('all','All cybersecurity records')}</select></label><label>Record type<select id="history-category">${option('all','All types')}${['Incident','Vulnerability','Advisory','Patch','News'].map(value=>option(value,value==='News'?'Cybersecurity reporting':value)).join('')}</select></label></div><div class="history-layout"><aside class="history-calendar-panel" aria-label="Choose a date"><div class="history-month-nav"><button class="button subtle" data-history-month="-1" aria-label="Previous month">‹</button><label class="sr-only" for="history-month">Month</label><input id="history-month" type="month" min="1900-01" max="2100-12"><button class="button subtle" data-history-month="1" aria-label="Next month">›</button></div><h2 id="history-month-title"></h2><div class="history-weekdays" aria-hidden="true">${['Mon','Tue','Wed','Thu','Fri','Sat','Sun'].map(day=>`<span>${day}</span>`).join('')}</div><div class="history-calendar" id="history-calendar"></div><p id="history-month-summary" class="history-calendar-caption"></p><button class="button subtle history-latest" data-history-latest>Jump to latest record</button><p class="quality-notice">Select a date to view its records. A number indicates recorded milestones or publications on that day.</p></aside><section class="history-agenda" aria-label="Dated cybersecurity records"><header class="history-agenda-header"><div><span class="eyebrow" id="history-basis-label"></span><h2 id="history-agenda-title"></h2><p id="history-result-count" role="status" aria-live="polite"></p></div><button class="button subtle" id="history-clear-day" data-history-clear>Show whole month</button></header><div id="history-records"></div><button class="button subtle" id="history-more" data-history-more>Show more records</button></section></div></div>`;
    root().addEventListener('input',event=>{if(event.target.id==='history-search'){filters.query=event.target.value;limit=36;renderContent();}});
    root().addEventListener('change',event=>{
      for(const key of ['basis','scope','category'])if(event.target.id===`history-${key}`){filters[key]=event.target.value;selectedDay='';limit=36;renderContent();return;}
      if(event.target.id==='history-month'&&/^\d{4}-(?:0[1-9]|1[0-2])$/.test(event.target.value)){month=event.target.value;selectedDay='';limit=36;renderContent();}
    });
    root().addEventListener('click',event=>{
      const button=event.target.closest('button');if(!button)return;
      if(button.dataset.historyMonth){month=shiftMonth(month,Number(button.dataset.historyMonth));selectedDay='';limit=36;renderContent();}
      if(button.dataset.historyDay){selectedDay=button.dataset.historyDay;month=selectedDay.slice(0,7);limit=36;renderContent();root().querySelector(`[data-history-day="${selectedDay}"]`)?.focus({preventScroll:true});}
      if(button.hasAttribute('data-history-clear')){selectedDay='';limit=36;renderContent();}
      if(button.hasAttribute('data-history-latest')){const latest=items()[0];if(latest){month=latest.day.slice(0,7);selectedDay=latest.day;limit=36;renderContent();}}
      if(button.hasAttribute('data-history-more')){limit+=36;renderAgenda();}
    });
    root().addEventListener('keydown',event=>{
      const day=event.target.dataset.historyDay;if(!day)return;
      const offset={ArrowLeft:-1,ArrowRight:1,ArrowUp:-7,ArrowDown:7}[event.key];if(!offset)return;
      event.preventDefault();const next=new Date(day+'T12:00:00Z');next.setUTCDate(next.getUTCDate()+offset);const target=next.toISOString().slice(0,10);
      if(!target.startsWith(month)){month=target.slice(0,7);selectedDay='';renderContent();}
      root().querySelector(`[data-history-day="${target}"]`)?.focus({preventScroll:true});
    });mounted=true;
  }
  function renderAgenda() {
    const records=currentItems(),shown=records.slice(0,limit),groups=new Map();
    for(const item of shown){if(!groups.has(item.day))groups.set(item.day,[]);groups.get(item.day).push(item);}
    root().querySelector('#history-basis-label').textContent=filters.basis==='milestones'?'REPORTED MILESTONES':'PUBLICATION DATES';
    root().querySelector('#history-agenda-title').textContent=selectedDay?dateLabel(selectedDay):monthLabel(month);
    root().querySelector('#history-result-count').textContent=`${records.length} ${filters.basis==='milestones'?'milestones':'publications'} · ${new Set(records.map(item=>item.event.id)).size} distinct records`;
    root().querySelector('#history-clear-day').hidden=!selectedDay;
    root().querySelector('#history-more').hidden=records.length<=limit;
    root().querySelector('#history-records').innerHTML=records.length?[...groups].map(([day,entries])=>`<section class="history-day-group"><h3><time datetime="${day}">${h(dateLabel(day))}</time><span>${entries.length}${shown.length<records.length?' shown':''}</span></h3>${entries.map(item=>{
      const event=item.event,original=event.sources?.find(source=>safeURL(source.url));
      return `<article class="history-card"><div class="history-card-meta"><span class="badge ${event.severity==='unknown'?'news-badge':`severity-${h(event.severity)}`}">${event.category==='News'?'REPORT':event.severity==='unknown'?'UNRATED':h(event.severity.toUpperCase())}</span><span>${h(event.category)}</span>${event.exploited?'<span>Exploitation reported</span>':''}</div><p class="history-milestone">${h(item.title)}</p><h4 class="history-title"><button data-open-event="${h(event.id)}">${h(event.title)}</button></h4><p class="history-summary">${h(item.description||event.summary)}</p><div class="history-card-actions"><span>${h(item.source?.name||event.organization)}</span><button data-open-event="${h(event.id)}">Open record →</button>${original?`<a href="${h(safeURL(original.url))}" target="_blank" rel="noopener noreferrer">Source <span aria-hidden="true">↗</span></a>`:''}</div></article>`;
    }).join('')}</section>`).join(''):`<div class="history-empty"><h3>No matching ${filters.basis==='milestones'?'milestones':'publications'} for this ${selectedDay?'date':'month'}.</h3><p>${filters.basis==='milestones'?'Milestones require a reviewed timeline with a documented date. Try Publication dates for wider reporting, or jump to the latest matching record.':'Try another date, broaden the filters, or jump to the latest matching record.'}</p></div>`;
    onResults(records.length);
  }
  function renderContent() {
    const all=items();if(!month)month=(all[0]?.day||calendarDate(new Date().toISOString())).slice(0,7);
    const counts=new Map();for(const item of all)counts.set(item.day,(counts.get(item.day)||0)+1);
    const today=calendarDate(new Date().toISOString());
    root().querySelector('#history-month').value=month;
    root().querySelector('#history-month-title').textContent=monthLabel(month);
    root().querySelector('#history-calendar').innerHTML=monthCalendar(month).map(cell=>`<button class="history-day${cell.inMonth?'':' is-outside'}${cell.day===selectedDay?' is-selected':''}${cell.day===today?' is-today':''}" data-history-day="${cell.day}" aria-pressed="${cell.day===selectedDay}" ${cell.day===today?'aria-current="date"':''} aria-label="${h(dateLabel(cell.day))}, ${counts.get(cell.day)||0} ${filters.basis==='milestones'?'milestones':'publications'}"><span>${cell.number}</span>${counts.has(cell.day)?`<strong>${counts.get(cell.day)}</strong>`:''}</button>`).join('');
    const inMonth=all.filter(item=>item.day.startsWith(month));
    root().querySelector('#history-month-summary').textContent=`${inMonth.length} ${filters.basis==='milestones'?'milestones':'publications'} across ${new Set(inMonth.map(item=>item.day)).size} days this month.`;
    root().querySelector('[data-history-latest]').disabled=!all.length;
    renderAgenda();
  }
  function render(){mount();renderContent();}
  return {render,reset:()=>{Object.assign(filters,{query:'',basis:'milestones',scope:'major',category:'all'});selectedDay='';month='';limit=36;if(mounted){root().querySelector('#history-search').value='';for(const key of ['basis','scope','category'])root().querySelector(`#history-${key}`).value=filters[key];}},events:()=>[...new Map(currentItems().map(item=>[item.event.id,item.event])).values()],items:currentItems,focusSearch:()=>{mount();root().querySelector('#history-search').focus();}};
}
