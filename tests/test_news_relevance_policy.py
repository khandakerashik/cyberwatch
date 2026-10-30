"""Editorial relevance boundaries and parity between refresh and legacy UI."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from scripts.source_catalog import news_relevance, record_news_relevance
from scripts.validate_data import validate_event

ROOT = Path(__file__).resolve().parents[1]

CASES = [
    ('GM cracks the petty cash box for multistate driver tracking settlement', 'The regulator said it compromised consumer privacy.', False),
    ('French privacy watchdog fines retailer for tracking app users without consent', '', False),
    ('Anthropic IPO filing', 'Investors discuss artificial intelligence software. ' + 'Prospectus information. ' * 100 + 'A security vulnerability could expose customers.', False),
    ('Apple faces economic vulnerabilities', 'The software business is slowing.', False),
    ('Teen hacks trees in local park', '', False),
    ('An apt response from an executive', 'The company sells software.', False),
    ('Stock exchange visitor loses wallet', 'Police investigate the theft of a physical wallet.', False),
    ('Exchange hacked', '', True),
    ('Crypto giant Binance hit by $6.3bn hack suspected to be largest in history', '', True),
    ('Company reaches a settlement after a data breach', '', True),
    ('Company reaches a settlement', 'Hackers stole customer account records in the incident.', True),
    ('Five life hacks', 'Malware hidden in downloaded instructions.', True),
    ('Five life hacks', 'Simple kitchen tips for your routine.', False),
    ('Claude Code extension poisoned with persistent SSH backdoor', '', True),
    ('SS7 and Diameter attacks expose mobile phone communications', '', True),
    ('26,400 cloud and AI credentials exposed in public repositories', '', True),
    ('New prompt injection techniques cover agent-planning attacks', '', True),
    ('Passkeys are better than passwords', '', True),
    ('Threat modeling with four questions', '', True),
    ('Why CTF competitions matter', '', True),
    ('How attackers bypass LLM safety classifiers', '', True),
    ('Drupal warns of critical Commerce Core flaw exploited in attacks', '', True),
    ('Details of thousands of officials leaked in major hack', '', True),
    ('Bangladesh Bank keeps website offline amid global cyber alert', '', True),
    ('সাইবার নিরাপত্তা বিষয়ক প্রশিক্ষণ অনুষ্ঠিত', '', True),
    ('La cybersécurité des entreprises', '', True),
]


class RelevancePolicyTests(unittest.TestCase):
    def test_policy_excludes_noise_and_keeps_security_context(self):
        for title, body, expected in CASES:
            with self.subTest(title=title):
                self.assertEqual(news_relevance(title, body)['relevant'], expected)

    @unittest.skipUnless(shutil.which('node'), 'Node is needed for browser/collector parity')
    def test_browser_and_collector_agree_on_corpus_and_bundled_records(self):
        snapshot = json.loads((ROOT / 'dist/data/incidents.json').read_text())
        records = [dict(title=title, description=body) for title, body, _ in CASES]
        records += [event for event in snapshot['events'] if event.get('stream') == 'news' or event.get('category') == 'News']
        program = """
import fs from 'node:fs';
import {evaluateNewsRelevance,publisherLead} from './dist/news-relevance.js';
const records=JSON.parse(fs.readFileSync(0,'utf8'));
process.stdout.write(JSON.stringify(records.map(event=>evaluateNewsRelevance(event.title,publisherLead(event)))));
"""
        result = subprocess.run(['node', '--input-type=module', '-e', program], cwd=ROOT,
                                input=json.dumps(records), text=True, capture_output=True, check=True, timeout=10)
        actual = json.loads(result.stdout)
        for event, browser in zip(records, actual):
            with self.subTest(title=event['title']):
                self.assertEqual(browser, record_news_relevance(event))

    def test_schema_rejects_coerced_or_unbounded_relevance_metadata(self):
        event = json.loads((ROOT / 'data/curated.json').read_text())[0]
        valid = news_relevance('Data breach disclosed')
        event['newsRelevance'] = valid
        validate_event(event)
        for change in ({'version': True}, {'version': 2}, {'relevant': 'true'},
                       {'reason': ''}, {'reason': 'x' * 501}, {'matchedKeywords': [None]}):
            candidate = deepcopy(event)
            candidate['newsRelevance'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_event(candidate)


if __name__ == '__main__':
    unittest.main()
