"""Newsboard source matching, official advisory adapters and retention contracts."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from source_catalog import CATALOG_PATH, load_sources, matched_keywords, public_endpoint
from fetch_feeds import (BASE_SOURCES, SOURCES, assemble, collect_source, content_fingerprint,
    fair_limit, feed_event, parse_atom, parse_feed, parse_nginx, parse_rss, retain_source_records)
from validate_data import validate_snapshot


def source(identifier):
    return next(item for item in SOURCES if item['id'] == identifier)


def rss(title='Exchange hacked; customer accounts exposed', body='An investigation follows a data breach.', url='https://www.bbc.com/news/articles/example', date='Fri, 30 Oct 2026 08:00:00 GMT'):
    return f'<rss><channel><item><title>{title}</title><link>{url}</link><description>{body}</description><pubDate>{date}</pubDate></item></channel></rss>'.encode()


class NewsSourceTests(unittest.TestCase):
    def test_required_sources_and_multiple_bbc_sections_exist(self):
        ids = {item['id'] for item in SOURCES}
        self.assertTrue({'bbc-technology', 'bbc-business', 'bbc-world', 'washington-post-technology',
            'washington-post-world', 'nginx', 'python-security', 'gitlab-security', 'nodejs-security', 'php-security'} <= ids)
        self.assertEqual(len(ids), len(SOURCES))
        for identifier in ('nginx', 'python-security', 'gitlab-security', 'nodejs-security'):
            self.assertEqual(source(identifier)['sourceType'], 'vendor')
            self.assertEqual(source(identifier)['stream'], 'intelligence')

    def test_keyword_families_and_crypto_headline(self):
        examples = {'Crypto giant Example hit by multi-billion hack': 'hack',
            'Group hacks airline accounts': 'hack', 'Agency hit by cyber-attack': 'cyberattack',
            'A major data breach reported': 'data breach', 'Hospital hit by ransomware': 'ransomware',
            'Phishing campaign steals credentials': 'phishing', 'Botnet DDoS disrupts services': 'DDoS',
            'Browser zero day disclosed': 'zero-day', 'Software vulnerability CVE-2026-12345': 'vulnerability',
            'Stolen wallet funds investigated after cryptocurrency theft': 'cryptocurrency theft',
            'Trading pauses after a software vendor was compromised': 'system compromise'}
        for title, expected in examples.items():
            with self.subTest(title=title):
                self.assertIn(expected, matched_keywords(title))
        self.assertIn('malware', matched_keywords('Five life hacks', 'Malware hidden in downloaded instructions'))

    def test_unrelated_life_hacks_and_generic_economic_vulnerability_excluded(self):
        for title in ('Five life hacks for travel', 'Cooking hacks to save time', 'A hackathon for students',
                      'Hack your sleep routine', 'A vulnerable economy', 'Economic vulnerabilities in emerging markets',
                      'Officials discuss a border security incident'):
            with self.subTest(title=title):
                self.assertEqual(matched_keywords(title), [])
        self.assertEqual(matched_keywords('New computer security bulletin', additional=['security bulletin']), ['security bulletin'])
        self.assertEqual(matched_keywords('Ransomware training', excludes=['training']), [])

    def test_bbc_news_is_unrated_and_does_not_become_confirmed_incident(self):
        event = parse_rss(rss(), source('bbc-business'))[0]
        self.assertEqual(event['category'], 'News')
        self.assertEqual(event['stream'], 'news')
        self.assertEqual(event['sourceType'], 'mainstream')
        self.assertEqual(event['confidence'], 'reported')
        self.assertEqual(event['severity'], 'unknown')
        self.assertFalse(event['exploited'])
        self.assertIn('hack', event['matchedKeywords'])

    def test_filtered_zero_match_is_success_but_error_pages_are_not(self):
        events, registry = collect_source(source('bbc-world'), {}, '2026-10-30T10:00:00Z',
            fetcher=lambda _: rss('Football team wins final', 'Fans celebrate.'))
        self.assertEqual(events, [])
        self.assertEqual(registry['status'], 'ok')
        self.assertEqual(registry['lastSuccessAt'], '2026-10-30T10:00:00Z')
        self.assertEqual(parse_rss(b'<rss><channel/></rss>', source('bbc-world')), [])
        for payload in (b'<html><body>Access denied</body></html>', b'<rss><channel><item><title>Hacked</title><link>https://bbc.com/a</link></item></channel></rss>'):
            with self.assertRaises(ValueError):
                parse_rss(payload, source('bbc-world'))

    def test_feed_images_and_content_do_not_allow_script_markup(self):
        payload = b'''<rss xmlns:media="http://search.yahoo.com/mrss/" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><item>
          <title>Cyberattack investigation</title><link>https://www.bbc.com/news/example</link><pubDate>Fri, 30 Oct 2026 08:00:00 GMT</pubDate>
          <description>&lt;p&gt;Published summary.&lt;script&gt;steal()&lt;/script&gt;&lt;/p&gt;</description>
          <content:encoded>&lt;p&gt;Publisher story text.&lt;/p&gt;</content:encoded>
          <media:content url="https://ichef.bbci.co.uk/news/cover.jpg" medium="image"><media:credit>Publisher photographer</media:credit></media:content>
          </item></channel></rss>'''
        event = parse_rss(payload, source('bbc-world'))[0]
        self.assertEqual(event['article']['status'], 'excerpt')
        self.assertEqual(event['article']['images'][0]['url'], 'https://ichef.bbci.co.uk/news/cover.jpg')
        self.assertNotIn('steal()', json.dumps(event))
        self.assertNotIn('<script>', json.dumps(event))

    def test_node_headline_only_security_feed_does_not_drop_advisory(self):
        payload = b'''<rss><channel><item><title>Wednesday Security Releases</title>
          <link>https://nodejs.org/en/blog/vulnerability/october-security-releases</link><pubDate>Wed, 21 Oct 2026 22:00:00 GMT</pubDate></item>
          <item><title>Node.js 27.0.0 Alpha</title><link>https://nodejs.org/en/blog/release/alpha</link><pubDate>Thu, 29 Oct 2026 12:00:00 GMT</pubDate></item></channel></rss>'''
        events = parse_rss(payload, source('nodejs-security'))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['category'], 'Advisory')
        self.assertEqual(events[0]['organization'], 'Node.js')
        self.assertEqual(events[0]['sourceType'], 'vendor')
        self.assertEqual(events[0]['article']['status'], 'unavailable')

    def test_python_security_release_filter_skips_feature_only_releases(self):
        events = parse_rss(rss('Python 3 release', 'This is a security release.'), source('python-releases'))
        self.assertEqual(events[0]['organization'], 'Python')
        self.assertEqual(parse_rss(rss('Python alpha available', 'New syntax and experimental features.'), source('python-releases')), [])

    def test_gitlab_atom_uses_explicit_security_evidence(self):
        payload = b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>GitLab patch release</title>
          <link href="https://docs.gitlab.com/releases/patch/"/><published>2026-10-29T00:00:00Z</published>
          <content type="html">&lt;p&gt;This release resolves security vulnerabilities CVE-2026-12345.&lt;/p&gt;</content></entry>
          <entry><title>GitLab monthly features</title><link href="https://docs.gitlab.com/releases/monthly/"/><published>2026-10-28T00:00:00Z</published><content>New product capabilities.</content></entry></feed>'''
        events = parse_atom(payload, source('gitlab-security'))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['cves'], ['CVE-2026-12345'])
        self.assertEqual(events[0]['stream'], 'intelligence')
        self.assertEqual(events[0]['organization'], 'GitLab')

    def test_nginx_dates_come_from_dated_cve_release_notes(self):
        advisory = b'''<html><p>Buffer overflow in a module<br>Severity: medium<br><a href="https://www.cve.org/CVERecord?id=CVE-2026-12345">CVE-2026-12345</a><br>Not vulnerable: 1.30.1+<br>Vulnerable: 1.30.0</p></html>'''
        changes = b'''Changes with nginx 1.30.1                     21 Oct 2026\n\n Security: fixed overflow (CVE-2026-12345).\n'''
        event = parse_nginx(advisory, source('nginx'), changes)[0]
        self.assertEqual(event['id'], 'nginx-cve-2026-12345')
        self.assertEqual(event['publishedAt'], '2026-10-21T00:00:00Z')
        self.assertEqual(event['severity'], 'medium')
        self.assertIn('fixed-release date', event['evidenceNote'])
        self.assertEqual(event['technicalDetails']['affectedSystems'], ['Vulnerable: 1.30.0'])
        with self.assertRaises(ValueError):
            parse_nginx(advisory, source('nginx'), b'Undated changes mentioning CVE-2026-12345')

    def test_auto_parser_accepts_rss_when_an_atom_named_endpoint_changes_format(self):
        self.assertEqual(len(parse_feed(rss(), source('the-register'))), 1)

    def test_retention_carries_rotated_news_without_redating_and_expires_old_items(self):
        src = source('bbc-world')
        event = parse_rss(rss(date='Fri, 23 Oct 2026 08:00:00 GMT'), src)[0]
        previous = {'events': [event], 'sources': [{'id': src['id'], 'lastSuccessAt': '2026-10-23T09:00:00Z'}]}
        events, registry = collect_source(src, previous, '2026-10-30T10:00:00Z', fetcher=lambda _: rss('Weather update', 'A sunny day.'))
        self.assertEqual(events, [event])
        self.assertEqual(events[0]['publishedAt'], '2026-10-23T08:00:00Z')
        self.assertEqual(registry['status'], 'ok')
        self.assertEqual(retain_source_records(src, [], previous, '2026-12-01T00:00:00Z'), [])

    def test_failure_retains_recent_records_but_not_new_success_timestamp(self):
        src = source('washington-post-technology')
        event = parse_rss(rss(), src)[0]
        previous = {'events': [event], 'sources': [{'id': src['id'], 'lastSuccessAt': '2026-10-30T09:00:00Z'}]}
        def offline(_):
            raise OSError('unavailable')
        events, registry = collect_source(src, previous, '2026-10-30T10:00:00Z', fetcher=offline)
        self.assertEqual(events, [event])
        self.assertEqual(registry['status'], 'error')
        self.assertEqual(registry['lastSuccessAt'], '2026-10-30T09:00:00Z')

    def test_bbc_cross_section_duplicate_is_merged_without_losing_independent_report(self):
        results = [collect_source(source(identifier), {}, '2026-10-30T10:00:00Z', fetcher=lambda _: rss())
            for identifier in ('bbc-technology', 'bbc-world', 'bbc-business')]
        results.append(collect_source(source('guardian-security'), {}, '2026-10-30T10:00:00Z',
            fetcher=lambda _: rss(url='https://www.theguardian.com/technology/security-story')))
        snapshot = assemble(results, [], '2026-10-30T10:00:00Z', 100)
        self.assertEqual(len(snapshot['events']), 2)
        validate_snapshot(snapshot)

    def test_fair_limit_keeps_quieter_official_advisory_channel(self):
        news = parse_rss(rss(), source('bbc-world'))[0]
        events = [dict(news, id='news-'+str(index), publishedAt='2026-10-30T08:00:00Z', updatedAt='2026-10-30T08:00:00Z') for index in range(50)]
        advisory = feed_event(source('python-security'), 'Python security fix', 'CVE-2026-12345 fixed.', 'https://www.python.org/security/example', '2026-09-30')
        events.append(advisory)
        selected = fair_limit(events, 5)
        self.assertEqual(len(selected), 5)
        self.assertIn(advisory['id'], {item['id'] for item in selected})

    def test_fetch_timestamp_does_not_make_unchanged_content_look_new(self):
        event = parse_rss(rss(), source('bbc-world'))[0]
        later = deepcopy(event)
        later['article']['fetchedAt'] = '2026-10-30T12:00:00Z'
        self.assertEqual(content_fingerprint([event]), content_fingerprint([later]))
        later['title'] = 'A new published headline'
        self.assertNotEqual(content_fingerprint([event]), content_fingerprint([later]))

    def test_local_catalogue_rejects_private_or_credentialed_feed_urls(self):
        for url in ('http://bbc.com/feed', 'https://127.0.0.1/feed', 'https://169.254.169.254/feed',
                    'https://localhost/feed', 'https://server.internal/feed', 'https://user:pass@bbc.com/feed',
                    'https://2130706433/feed', 'https://example.com:8080/feed'):
            with self.subTest(url=url):
                self.assertFalse(public_endpoint(url))
        self.assertTrue(public_endpoint('https://feeds.bbci.co.uk/news/technology/rss.xml'))
        config = json.loads(CATALOG_PATH.read_text())
        config['sources'][0]['feedUrls'] = ['https://127.0.0.1/feed']
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'catalogue.json'; path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                load_sources(BASE_SOURCES, path)


if __name__ == '__main__':
    unittest.main()
