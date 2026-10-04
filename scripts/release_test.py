#!/usr/bin/env python3
"""Keep model execution, citation contracts and task quality separate in releases."""
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import release


class AssistantReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='k957-release-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.receipt = self.root / 'validation.json'
        self.log = self.root / 'assistant_model_integration.log'
        self.result = {
            'schema': 'k957-assistant-evaluation/1', 'model': 'fixture', 'model_digest': 'a' * 64,
            'runtime': {'version': 'fixture'},
            'cases': [{'citation_contract': 'passed', 'task_success': True},
                      {'citation_contract': 'passed', 'task_success': False}],
            'signed_review': 'passed', 'index_unchanged': True,
            'task_successes': 1, 'task_total': 2, 'task_quality_result': 'failed',
            'scope': 'Synthetic quotations only',
        }
        self.step = {'name': 'assistant_model_integration', 'status': 'passed', 'log': self.log.name}

    def evaluate(self, steps=None):
        self.log.write_text(json.dumps(self.result), encoding='utf-8')
        with patch.object(release, 'ROOT', self.root):
            return release.assistant_evaluation(self.receipt, {'steps': steps if steps is not None else [self.step]})

    def test_task_failure_is_retained_separately_from_citation_success(self):
        result = self.evaluate()
        self.assertEqual(result['citation_contract_cases_passed'], 2)
        self.assertEqual(result['task_successes'], 1)
        self.assertEqual(result['task_quality_result'], 'failed')
        self.assertFalse(result['forensic_quality_validated'])
        self.assertEqual(result['sha256'], release.sha256(self.log))

    def test_unexecuted_model_is_not_reported_as_tested(self):
        self.assertIsNone(self.evaluate([]))
        self.assertIsNone(self.evaluate([self.step | {'status': 'skipped'}]))

    def test_inconsistent_counters_are_rejected(self):
        self.result['task_successes'] = 2
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_failed_citation_contract_is_rejected(self):
        self.result['cases'][0]['citation_contract'] = 'failed'
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_failed_review_or_changed_index_is_rejected(self):
        for field, value in [('signed_review', 'failed'), ('index_unchanged', False)]:
            with self.subTest(field=field):
                original = self.result[field]
                self.result[field] = value
                with self.assertRaises(ValueError):
                    self.evaluate()
                self.result[field] = original

    def test_log_traversal_and_duplicate_steps_are_rejected(self):
        with self.assertRaises(ValueError):
            self.evaluate([self.step | {'log': '../outside.log'}])
        with self.assertRaises(ValueError):
            self.evaluate([self.step, self.step])


if __name__ == '__main__':
    unittest.main()
