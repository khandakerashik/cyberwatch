from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from source_health import append_collection_history


class SourceHealthTests(unittest.TestCase):
    def source(self, **kwargs):
        return dict(kind='primary', status='ok', lastAttemptAt='2026-10-31T10:00:00Z', itemCount=0, **kwargs)

    def test_first_observation_is_one_real_check_even_when_empty(self):
        self.assertEqual(append_collection_history(self.source()), [
            {'at':'2026-10-31T10:00:00Z','status':'ok','recordCount':0}])

    def test_upgrade_seeds_only_the_recorded_legacy_attempt(self):
        prior = {'status':'error','lastAttemptAt':'2026-10-30T10:00:00Z','itemCount':4}
        checks = append_collection_history(self.source(), prior)
        self.assertEqual([row['status'] for row in checks], ['error','ok'])
        self.assertEqual(len(checks), 2)

    def test_reassembly_is_idempotent_and_does_not_count_a_browser_reload(self):
        source = self.source()
        source['collectionHistory'] = append_collection_history(source)
        self.assertEqual(append_collection_history(source, source), source['collectionHistory'])

    def test_bounded_ordered_history_ignores_future_or_malformed_samples(self):
        prior = {'collectionHistory':[{'at':f'2026-10-{day:02}T{hour:02}:00:00Z','status':'ok','recordCount':1}
                                      for day in (28,29,30) for hour in range(24)]}
        prior['collectionHistory'].append({'at':'2027-01-01T00:00:00Z','status':'ok','recordCount':1})
        prior['collectionHistory'].append({'at':'invalid','status':'error','recordCount':1})
        checks = append_collection_history(self.source(), prior)
        self.assertEqual(len(checks), 48)
        self.assertEqual(checks[-1]['at'], '2026-10-31T10:00:00Z')
        self.assertEqual(checks, sorted(checks, key=lambda row:row['at']))

    def test_curated_records_do_not_claim_automated_success(self):
        self.assertEqual(append_collection_history({'kind':'curated','status':'snapshot'}), [])

    def test_unknown_or_missing_attempt_is_not_a_failure_or_success(self):
        self.assertEqual(append_collection_history({'status':'ok','itemCount':4}), [])

    def test_mixed_timestamp_precision_keeps_actual_chronological_order(self):
        prior={'collectionHistory':[{'at':'2026-10-31T10:00:00Z','status':'ok','recordCount':1}]}
        current={'kind':'primary','status':'error','lastAttemptAt':'2026-10-31T10:00:00.500000Z','itemCount':1}
        checks=append_collection_history(current,prior)
        self.assertEqual(len(checks),2)
        self.assertEqual([check['status'] for check in checks],['ok','error'])

