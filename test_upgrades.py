import copy
import tempfile
import unittest
from pathlib import Path

import lab
import upgrades

CHANGE = {'group': 'org.apache.commons', 'artifact': 'commons-lang3',
          'from': '3.12.0', 'to': '3.17.0'}
POM = '''<project xmlns="http://maven.apache.org/POM/4.0.0">
<modelVersion>4.0.0</modelVersion>
<groupId>lab</groupId><artifactId>demo</artifactId><version>1</version>
<dependencies><dependency>
<groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>
<version>3.12.0</version>
</dependency></dependencies>
</project>
'''


class UpgradeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name) / 'repo'
        self.repo.mkdir()
        lab.git(self.repo, 'init', '-b', 'main')
        (self.repo / 'pom.xml').write_text(POM)
        (self.repo / 'App.java').write_text('class App {}\n')
        self.commit('Initial')
        lab.git(self.repo, 'branch', 'develop')
        self.plan = upgrades.create_plan(self.repo, 'main', [CHANGE])

    def commit(self, message):
        lab.git(self.repo, 'add', '.')
        lab.git(self.repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-m', message)
        return lab.git(self.repo, 'rev-parse', 'HEAD')

    def test_requires_approval(self):
        with self.assertRaisesRegex(ValueError, 'approval'):
            upgrades.apply(self.plan)

    def test_apply_keeps_target_and_working_copy_unchanged(self):
        before = lab.git(self.repo, 'rev-parse', 'main')
        approved = upgrades.approve(self.plan, 'tester')
        result = upgrades.apply(approved)
        self.assertEqual(result['status'], 'awaiting_verification')
        self.assertFalse(result['mr_created'])
        self.assertEqual(lab.git(self.repo, 'rev-parse', 'main'), before)
        self.assertEqual((self.repo / 'pom.xml').read_text(), POM)
        self.assertIn('3.17.0', lab.git(self.repo, 'show', result['commit'] + ':pom.xml'))
        self.assertEqual(lab.git(self.repo, 'status', '--porcelain'), '')

    def test_batch_selection_and_common_approval(self):
        batch = upgrades.create_batch([
            {'repo': str(self.repo), 'target': 'main', 'changes': [CHANGE]},
            {'repo': str(self.repo), 'target': 'develop', 'changes': [CHANGE], 'selected': False},
        ])
        self.assertEqual(len(batch['plans']), 1)
        with self.assertRaises(ValueError):
            upgrades.apply_batch(batch)
        result = upgrades.apply_batch(upgrades.approve_batch(batch, 'tester'))
        self.assertEqual(result['results'][0]['status'], 'awaiting_verification')

    def test_batch_failure_does_not_block_other_target(self):
        batch = upgrades.create_batch([
            {'repo': str(self.repo), 'target': target, 'changes': [CHANGE]}
            for target in ('main', 'develop')
        ])
        upgrades.approve_batch(batch, 'tester')
        (self.repo / 'App.java').write_text('class App { int newer; }\n')
        self.commit('Move main')
        result = upgrades.apply_batch(batch)
        self.assertEqual([r['status'] for r in result['results']], ['failed', 'awaiting_verification'])

    def test_develop_target(self):
        plan = upgrades.create_plan(self.repo, 'develop', [CHANGE])
        result = upgrades.apply(upgrades.approve(plan, 'tester'))
        self.assertEqual(result['status'], 'awaiting_verification')

    def test_tampering_invalidates_approval(self):
        approved = upgrades.approve(self.plan, 'tester')
        approved['changes'][0] = dict(CHANGE, to='4.0.0')
        with self.assertRaisesRegex(ValueError, 'changed'):
            upgrades.verify_plan(approved, approved=True)

    def test_moved_branch_requires_new_plan(self):
        upgrades.approve(self.plan, 'tester')
        (self.repo / 'App.java').write_text('class App { int n; }\n')
        self.commit('New code')
        with self.assertRaisesRegex(ValueError, 'moved'):
            upgrades.apply(self.plan)

    def test_source_changes_rejected_on_main(self):
        upgrades.approve(self.plan, 'tester')
        (self.repo / 'pom.xml').write_text(upgrades.update_pom(POM, [CHANGE]))
        (self.repo / 'App.java').write_text('class App { int n; }\n')
        candidate = self.commit('Unexpected source change')
        # Restore main's baseline; keep the candidate reachable by its hash.
        lab.git(self.repo, 'branch', 'candidate', candidate)
        lab.git(self.repo, 'reset', '--hard', self.plan['base_commit'])
        with self.assertRaisesRegex(ValueError, 'pom.xml only'):
            upgrades.validate_candidate(self.repo, self.plan, candidate)

    def test_unapproved_pom_changes_rejected(self):
        after = upgrades.update_pom(POM, [CHANGE]).replace('<version>1</version>', '<version>2</version>')
        with self.assertRaisesRegex(ValueError, 'beyond'):
            upgrades.validate_pom(POM, after, [CHANGE])

    def test_parent_and_bom_changes_rejected(self):
        for addition in (
            '<parent><groupId>x</groupId><artifactId>y</artifactId><version>1</version></parent>',
            '<dependencyManagement><dependencies><dependency><groupId>x</groupId>'
            '<artifactId>bom</artifactId><version>1</version><type>pom</type>'
            '<scope>import</scope></dependency></dependencies></dependencyManagement>',
        ):
            before = POM.replace('</project>', addition + '</project>')
            after = upgrades.update_pom(before, [CHANGE]).replace('<version>1</version>', '<version>2</version>')
            with self.subTest(addition=addition), self.assertRaises(ValueError):
                upgrades.validate_pom(before, after, [CHANGE])

    def test_property_and_duplicate_changes_rejected(self):
        with self.assertRaises(ValueError):
            upgrades.update_pom(POM.replace('3.12.0', '${commons.version}'), [CHANGE])
        with self.assertRaises(ValueError):
            upgrades.validate_pom(POM, POM, [CHANGE, copy.deepcopy(CHANGE)])


if __name__ == '__main__':
    unittest.main()
