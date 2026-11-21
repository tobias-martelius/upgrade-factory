import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import inventory
import lab
import upgrades
import verification
from test_upgrades import CHANGE, POM


def sbom(version='3.17.0'):
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'components': [{'type': 'library', 'group': 'org.apache.commons',
                            'name': 'commons-lang3', 'version': version,
                            'purl': 'pkg:maven/org.apache.commons/commons-lang3@' + version}]}


def scan(vulnerabilities=None):
    return {'SchemaVersion': 2, 'Results': [{'Vulnerabilities': vulnerabilities or []}]}


class VerificationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        lab.git(self.repo, 'init', '-b', 'main')
        (self.repo / 'pom.xml').write_text(POM)
        lab.git(self.repo, 'add', '.')
        lab.git(self.repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-m', 'Fixture')
        self.plan = upgrades.approve(upgrades.create_plan(self.repo, 'main', [CHANGE]), 'tester')
        upgrades.apply(self.plan)
        self.output = self.root / 'output'
        self.database = self.root / 'inventory.sqlite'

    def fake_runner(self, command, cwd, log, timeout=900):
        """Explicit test double. Never used by production CLI."""
        Path(log).write_text('TEST DOUBLE: no actual external command executed\n')
        target = cwd / 'target'
        target.mkdir(exist_ok=True)
        if 'verify' in command:
            reports = target / 'surefire-reports'
            reports.mkdir()
            (reports / 'TEST-App.xml').write_text(
                '<testsuite tests="1" failures="0" errors="0" skipped="0"/>')
        elif verification.CYCLONEDX in command:
            version = '3.17.0' if '3.17.0' in (cwd / 'pom.xml').read_text() else '3.12.0'
            (target / 'sbom.json').write_text(json.dumps(sbom(version)))
        else:
            Path(command[command.index('--output') + 1]).write_text(json.dumps(scan()))

    def test_verification_and_central_inventory(self):
        report = verification.verify(self.plan, self.output, self.database,
                                     runner=self.fake_runner, check_tools=False)
        self.assertEqual(report['status'], 'awaiting_dependency_review', report)
        self.assertFalse(report['mr_created'])
        self.assertTrue(report['security']['passed'])
        snapshots = inventory.export_inventory(self.database)['snapshots']
        self.assertEqual({s['role'] for s in snapshots}, {'baseline', 'candidate'})
        self.assertEqual(len({s['commit'] for s in snapshots}), 2)
        self.assertEqual(len(report['dependency_delta']['added']), 1)
        # Worktrees are cleaned; target main is unchanged.
        self.assertEqual((self.repo / 'pom.xml').read_text(), POM)
        self.assertEqual(len(lab.git(self.repo, 'worktree', 'list').splitlines()), 1)

    def test_missing_tools_block_instead_of_pass(self):
        with patch('verification.shutil.which', return_value=None):
            report = verification.verify(self.plan, self.output, self.database)
        self.assertEqual(report['status'], 'blocked')
        self.assertIn('mvn, trivy', report['error'])
        self.assertFalse(self.database.exists())

    def test_build_failure_stops_pipeline(self):
        def fail(*args):
            raise ValueError('Build failed')
        report = verification.verify(self.plan, self.output, self.database,
                                     runner=fail, check_tools=False)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['error'], 'Build failed')
        self.assertFalse(self.database.exists())

    def test_missing_tests_rejected(self):
        with self.assertRaises(ValueError):
            verification.test_summary(self.root)
        reports = self.root / 'target/surefire-reports'
        reports.mkdir(parents=True)
        path = reports / 'TEST-X.xml'
        for attributes in ['tests="1" skipped="1"', 'tests="1" errors="1"']:
            path.write_text('<testsuite ' + attributes + '/>')
            with self.assertRaises(ValueError):
                verification.test_summary(self.root)

    def test_remaining_findings_and_introduced_high_block(self):
        vulnerability = {'VulnerabilityID': 'CVE-TEST-1', 'PkgName': 'commons-lang3',
                         'PkgIdentifier': {'PURL': 'pkg:maven/org.apache.commons/commons-lang3@3.17.0'},
                         'Severity': 'LOW'}
        result = verification.compare_security(scan(), scan([vulnerability]), [CHANGE])
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['remaining_on_changed_dependencies']), 1)
        vulnerability = dict(vulnerability, PkgName='other:library', PkgIdentifier={}, Severity='HIGH')
        result = verification.compare_security(scan(), scan([vulnerability]), [CHANGE])
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['introduced_high_or_critical']), 1)

    def test_invalid_scan_or_wrong_resolved_version_rejected(self):
        with self.assertRaises(ValueError):
            verification.findings({})
        with self.assertRaises(ValueError):
            verification.validate_resolved_versions(sbom('3.12.0'), [CHANGE], 'to')

    def test_inventory_preserves_provenance_and_deduplicates(self):
        path = self.root / 'sbom.json'
        path.write_text(json.dumps(sbom()))
        for _ in range(2):
            inventory.record(self.database, path, 'repo-a', 'main', 'sha1', 'baseline')
        inventory.record(self.database, path, 'repo-b', 'develop', 'sha2', 'candidate')
        export = inventory.export_inventory(self.database)
        self.assertEqual(len(export['snapshots']), 2)
        self.assertEqual({s['repo'] for s in export['snapshots']}, {'repo-a', 'repo-b'})
        central = inventory.export_cyclonedx(self.database)
        self.assertEqual(central['bomFormat'], 'CycloneDX')
        self.assertEqual(len(central['components']), 2)
        first, second = central['components']
        self.assertNotEqual(first['components'][0]['bom-ref'], second['components'][0]['bom-ref'])
        self.assertEqual(first['properties'][0]['value'], 'repo-a')
        self.assertEqual(len(central['dependencies']), 2)


if __name__ == '__main__':
    unittest.main()
