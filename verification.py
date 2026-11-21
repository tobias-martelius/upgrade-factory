"""Verify approved candidates using real Maven, CycloneDX and Trivy commands.

Only run against trusted local fixture repositories: a Git worktree is NOT an
OS sandbox. Maven plugins/tests execute code with the current user's permissions.
"""
import argparse
import copy
import json
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import inventory
import lab
import upgrades

CYCLONEDX = 'org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom'


def run_command(command, cwd, log, timeout=900):
    with Path(log).open('w') as stream:
        stream.write('$ ' + ' '.join(command) + '\n')
        stream.flush()
        process = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                                 timeout=timeout, check=False)
    if process.returncode:
        raise ValueError(f'Command failed ({process.returncode}); see {log}')


def test_summary(worktree):
    reports = list(Path(worktree).glob('**/target/surefire-reports/TEST-*.xml'))
    reports += list(Path(worktree).glob('**/target/failsafe-reports/TEST-*.xml'))
    total = {'tests': 0, 'failures': 0, 'errors': 0, 'skipped': 0}
    for report in reports:
        root = ET.parse(report).getroot()
        # Standard Surefire reports have testsuite at the root.
        suites = [root] if root.tag == 'testsuite' else root.findall('.//testsuite')
        for suite in suites:
            for key in total:
                total[key] += int(suite.get(key, '0'))
    if total['failures'] or total['errors'] or total['tests'] <= total['skipped']:
        raise ValueError('Tests failed or no executed tests were reported')
    return total


def findings(document):
    if not isinstance(document, dict) or document.get('SchemaVersion') != 2:
        raise ValueError('Expected Trivy JSON with SchemaVersion 2')
    results = document.get('Results', [])
    if not isinstance(results, list):
        raise ValueError('Invalid Trivy results')
    values = []
    for result in results:
        for item in result.get('Vulnerabilities') or []:
            package = item['PkgName']
            purl = item.get('PkgIdentifier', {}).get('PURL', '')
            if purl.startswith('pkg:maven/'):
                coordinates = unquote(purl[len('pkg:maven/'):].split('@')[0])
                package = coordinates.replace('/', ':')
            values.append({'id': item['VulnerabilityID'], 'package': package,
                           'version': item.get('InstalledVersion', ''),
                           'severity': item.get('Severity', 'UNKNOWN')})
    return values


def compare_security(baseline, candidate, changes):
    old = {(v['id'], v['package']) for v in findings(baseline)}
    current = findings(candidate)
    changed = {c['group'] + ':' + c['artifact'] for c in changes}
    remaining = [v for v in current if v['package'] in changed]
    introduced = [v for v in current if v['severity'] in ('HIGH', 'CRITICAL')
                  and (v['id'], v['package']) not in old]
    return {'passed': not remaining and not introduced,
            'remaining_on_changed_dependencies': remaining,
            'introduced_high_or_critical': introduced,
            'baseline_findings': len(findings(baseline)), 'candidate_findings': len(current)}


def components(document):
    values = set()

    def walk(items):
        for item in items:
            values.add((item.get('group', ''), item['name'], item.get('version', ''), item.get('purl', '')))
            walk(item.get('components', []))

    walk(document.get('components', []))
    return values


def validate_resolved_versions(document, changes, field):
    resolved = components(document)
    for change in changes:
        if not any(group == change['group'] and name == change['artifact'] and version == change[field]
                   for group, name, version, _ in resolved):
            raise ValueError('SBOM does not contain expected resolved dependency: ' + change['artifact'])


def dependency_delta(before, after):
    old, new = components(before), components(after)
    return {'removed': [list(x) for x in sorted(old - new)],
            'added': [list(x) for x in sorted(new - old)]}


def check_snapshot(repo, commit, output, runner=run_command):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='verify-upgrade-') as temporary:
        worktree = Path(temporary) / 'source'
        lab.git(repo, 'worktree', 'add', '--detach', str(worktree), commit)
        try:
            runner(['mvn', '-B', '-ntp', 'clean', 'verify', '-DskipTests=false',
                    '-Dmaven.test.skip=false', '-Dmaven.test.failure.ignore=false',
                    '-DfailIfNoTests=true'], worktree, output / 'build.log')
            tests = test_summary(worktree)
            runner(['mvn', '-B', '-ntp', CYCLONEDX, '-DoutputFormat=json',
                    '-DoutputName=sbom', '-DincludeTestScope=false'],
                   worktree, output / 'sbom.log')
            generated = worktree / 'target/sbom.json'
            inventory.read_sbom(generated)
            sbom = output / 'sbom.json'
            shutil.copyfile(generated, sbom)
            scan = output / 'trivy.json'
            runner(['trivy', 'sbom', '--scanners', 'vuln', '--format', 'json',
                    '--output', str(scan.resolve()), str(sbom.resolve())],
                   worktree, output / 'scan.log')
            scan_document = json.loads(scan.read_text())
            findings(scan_document)
            # Reject changes to tracked files caused by plugins/tests.
            if lab.git(worktree, 'status', '--porcelain', '--untracked-files=no'):
                raise ValueError('Build modified tracked source files')
            return {'tests': tests, 'sbom': str(sbom), 'scan': scan_document}
        finally:
            lab.git(repo, 'worktree', 'remove', '--force', str(worktree))


def verify(plan, output, database, runner=run_command, check_tools=True):
    output = Path(output).resolve() / plan['id']
    output.mkdir(parents=True, exist_ok=True)
    report = {'plan_id': plan['id'], 'repo': plan['repo'], 'target_branch': plan['target_branch'],
              'base_commit': plan['base_commit'], 'status': 'failed', 'mr_created': False,
              'at': datetime.now(timezone.utc).isoformat()}
    try:
        upgrades.verify_plan(plan, approved=True)
        branch = 'upgrade/' + plan['id'][:16]
        commit = lab.git(plan['repo'], 'rev-parse', '--verify', 'refs/heads/' + branch)
        upgrades.validate_candidate(plan['repo'], plan, commit)
        report.update({'branch': branch, 'candidate_commit': commit})
        if check_tools:
            missing = [name for name in ('mvn', 'trivy') if not shutil.which(name)]
            if missing:
                report['status'] = 'blocked'
                raise ValueError('Missing tools: ' + ', '.join(missing))
        snapshots = {}
        for role, sha in [('baseline', plan['base_commit']), ('candidate', commit)]:
            snapshot = check_snapshot(plan['repo'], sha, output / role, runner)
            validate_resolved_versions(inventory.read_sbom(snapshot['sbom']), plan['changes'],
                                       'from' if role == 'baseline' else 'to')
            report[role] = {'tests': snapshot['tests'], 'sbom': snapshot['sbom'],
                            'inventory_id': inventory.record(database, snapshot['sbom'], plan['repo'],
                                                             plan['target_branch'], sha, role)}
            snapshots[role] = snapshot
        report['dependency_delta'] = dependency_delta(
            inventory.read_sbom(snapshots['baseline']['sbom']),
            inventory.read_sbom(snapshots['candidate']['sbom']))
        report['security'] = compare_security(snapshots['baseline']['scan'],
                                              snapshots['candidate']['scan'], plan['changes'])
        if not report['security']['passed']:
            raise ValueError('Security policy failed; see security details')
        # Recheck after potentially long-running verification.
        upgrades.validate_candidate(plan['repo'], plan, commit)
        if lab.git(plan['repo'], 'rev-parse', 'refs/heads/' + branch) != commit:
            raise ValueError('Candidate branch moved during verification')
        # Dependency changes still need review; no implicit claim that a build proves safety.
        report['status'] = 'awaiting_dependency_review'
    except (ValueError, KeyError, OSError, ET.ParseError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def verify_batch(batch, output, database, workers=2):
    approval = batch.get('approval', {})
    if (batch['id'] != upgrades.digest(batch) or not approval.get('by')
            or approval.get('plan_id') != batch['id']):
        raise ValueError('Approval of this exact batch is required')

    def run(original):
        plan = copy.deepcopy(original)
        plan['approval'] = dict(approval, plan_id=plan['id'])
        return verify(plan, output, database)

    with ThreadPoolExecutor(max_workers=max(1, min(20, workers))) as executor:
        return {'batch_id': batch['id'], 'results': list(executor.map(run, batch['plans']))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', help='Approved plan or batch JSON')
    parser.add_argument('--output', default='.lab/verification')
    parser.add_argument('--database', default='.lab/inventory.sqlite')
    parser.add_argument('--workers', type=int, default=2)
    args = parser.parse_args()
    content = json.loads(Path(args.plan).read_text())
    try:
        result = (verify_batch(content, args.output, args.database, args.workers)
                  if content.get('kind') == 'batch' else verify(content, args.output, args.database))
        print(json.dumps(result, indent=2))
        results = result.get('results', [result])
        if any(r['status'] != 'awaiting_dependency_review' for r in results):
            parser.exit(1)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
