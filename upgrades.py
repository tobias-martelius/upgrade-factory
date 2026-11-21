"""Deterministic, approval-bound Maven version updates. No builds or AI execution."""
import argparse
import copy
import hashlib
import json
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import lab

NS = {'m': 'http://maven.apache.org/POM/4.0.0'}
POLICIES = {
    'main': {'source_changes': False, 'parent_or_bom': False, 'agent': False,
             'description': 'Approved direct dependency versions only; verification required.'},
    'develop': {'source_changes': True, 'parent_or_bom': True, 'agent': 'separate-approval',
                'description': 'Broader migrations require a separately approved recipe.'},
}


def digest(plan):
    content = {k: v for k, v in plan.items() if k not in ('approval', 'id')}
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def validate_change(change):
    if set(change) != {'group', 'artifact', 'from', 'to'}:
        raise ValueError('Each change needs exactly group, artifact, from, to')
    if not all(isinstance(v, str) and v and not re.search(r'[\s<>&$]', v) for v in change.values()):
        raise ValueError('Expected literal Maven coordinates and versions')
    if change['from'] == change['to']:
        raise ValueError('Version must change')


def parse_pom(text):
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValueError('DTD/entity declarations are unsupported')
    root = ET.fromstring(text)
    if root.tag != '{' + NS['m'] + '}project':
        raise ValueError('Expected a Maven project with XML namespace')
    return root


def dependency(root, change):
    matches = [node for node in root.findall('m:dependencies/m:dependency', NS)
               if node.findtext('m:groupId', namespaces=NS) == change['group']
               and node.findtext('m:artifactId', namespaces=NS) == change['artifact']]
    if len(matches) != 1:
        raise ValueError('Expected one direct dependency: ' + change['artifact'])
    node = matches[0]
    if node.findtext('m:type', namespaces=NS) == 'pom':
        raise ValueError('BOM/POM dependencies are not supported by this version-only engine')
    version = node.find('m:version', NS)
    if version is None or not version.text or '${' in version.text:
        raise ValueError('Only explicit direct dependency versions are supported')
    return version


def fingerprint(root):
    # Ignore XML formatting, but retain element order, values, and attributes.
    return (root.tag, tuple(sorted(root.attrib.items())), (root.text or '').strip(),
            tuple((fingerprint(child), (child.tail or '').strip()) for child in root))


def validate_pom(before, after, changes):
    expected, actual = parse_pom(before), parse_pom(after)
    seen = set()
    for change in changes:
        validate_change(change)
        key = change['group'], change['artifact']
        if key in seen:
            raise ValueError('Duplicate dependency in plan')
        seen.add(key)
        version = dependency(expected, change)
        if version.text != change['from']:
            raise ValueError('Baseline version differs from approved version')
        version.text = change['to']
    if fingerprint(expected) != fingerprint(actual):
        raise ValueError('POM contains changes beyond the approved dependency versions')


def update_pom(before, changes):
    """Preserve the original XML outside literal version text replacements."""
    parse_pom(before)
    after = before
    # Require conventional unprefixed dependency elements; fail closed otherwise.
    for change in changes:
        validate_change(change)
        pattern = re.compile(r'<dependency\b[^>]*>.*?</dependency>', re.DOTALL)
        replacements = 0

        def replace(match):
            nonlocal replacements
            block = match.group(0)
            try:
                node = ET.fromstring('<root xmlns="' + NS['m'] + '">' + block + '</root>')[0]
            except ET.ParseError:
                return block
            if (node.findtext('m:groupId', namespaces=NS), node.findtext('m:artifactId', namespaces=NS)) != (change['group'], change['artifact']):
                return block
            updated, count = re.subn(r'(<version>)' + re.escape(change['from']) + r'(</version>)',
                                     lambda m: m[1] + change['to'] + m[2], block)
            replacements += count
            return updated

        after = pattern.sub(replace, after)
        if replacements != 1:
            raise ValueError('Cannot safely edit literal dependency version')
    validate_pom(before, after, changes)
    return after


def branch_head(repo, branch):
    if branch not in POLICIES:
        raise ValueError('Target branch must be main or develop')
    return lab.git(repo, 'rev-parse', '--verify', 'refs/heads/' + branch)


def create_plan(repo, branch, changes):
    repo = str(Path(repo).resolve())
    head = branch_head(repo, branch)
    before = lab.git(repo, 'show', head + ':pom.xml')
    if not changes:
        raise ValueError('At least one version change is required')
    update_pom(before, changes)
    plan = {'schema': 1, 'repo': repo, 'target_branch': branch, 'base_commit': head,
            'policy': copy.deepcopy(POLICIES[branch]), 'changes': changes}
    plan['id'] = digest(plan)
    return plan


def verify_plan(plan, approved=False):
    if plan['id'] != digest(plan):
        raise ValueError('Plan has changed; regenerate and approve it again')
    if plan['policy'] != POLICIES.get(plan['target_branch']):
        raise ValueError('Policy has changed; a new approval is required')
    if branch_head(plan['repo'], plan['target_branch']) != plan['base_commit']:
        raise ValueError('Target branch has moved; regenerate and approve a new plan')
    if approved and (not plan.get('approval', {}).get('by') or
                     plan['approval'].get('plan_id') != plan['id']):
        raise ValueError('Explicit approval of this exact plan is required')


def approve(plan, actor):
    verify_plan(plan)
    if not actor.strip():
        raise ValueError('Approver is required')
    # Local development identity, not authenticated authorization.
    plan['approval'] = {'by': actor.strip(), 'plan_id': plan['id'],
                        'at': datetime.now(timezone.utc).isoformat()}
    return plan


def validate_candidate(repo, plan, candidate):
    verify_plan(plan, approved=True)
    paths = lab.git(repo, 'diff', '--name-only', plan['base_commit'], candidate).splitlines()
    if paths != ['pom.xml']:
        raise ValueError('Version-only engine permits changes to pom.xml only')
    before = lab.git(repo, 'show', plan['base_commit'] + ':pom.xml')
    after = lab.git(repo, 'show', candidate + ':pom.xml')
    validate_pom(before, after, plan['changes'])
    mode = lab.git(repo, 'ls-tree', candidate, '--', 'pom.xml').split()[0]
    old_mode = lab.git(repo, 'ls-tree', plan['base_commit'], '--', 'pom.xml').split()[0]
    if mode != old_mode:
        raise ValueError('File mode changes are not permitted')


def apply(plan):
    verify_plan(plan, approved=True)
    repo = plan['repo']
    branch = 'upgrade/' + plan['id'][:16]
    # Deterministic name makes repeated application fail rather than duplicate work.
    with tempfile.TemporaryDirectory(prefix='upgrade-lab-') as temporary:
        worktree = Path(temporary) / 'worktree'
        lab.git(repo, 'worktree', 'add', '-b', branch, str(worktree), plan['base_commit'])
        try:
            pom = worktree / 'pom.xml'
            pom.write_text(update_pom(pom.read_text(), plan['changes']))
            lab.git(worktree, 'add', '--', 'pom.xml')
            lab.git(worktree, '-c', 'user.name=Upgrade Lab', '-c', 'user.email=lab@example.invalid',
                    '-c', 'commit.gpgsign=false', 'commit', '-m', 'Apply approved plan ' + plan['id'])
            commit = lab.git(worktree, 'rev-parse', 'HEAD')
            validate_candidate(repo, plan, commit)
        finally:
            lab.git(repo, 'worktree', 'remove', '--force', str(worktree))
    return {'plan_id': plan['id'], 'branch': branch, 'commit': commit,
            'status': 'awaiting_verification', 'mr_created': False,
            'required_checks': ['build', 'tests', 'dependency-tree-review', 'sbom', 'security-scan']}


def create_batch(entries):
    plans = [create_plan(entry['repo'], entry['target'], entry['changes'])
             for entry in entries if entry.get('selected', True)]
    if not plans:
        raise ValueError('Select at least one repository/target')
    targets = [(p['repo'], p['target_branch']) for p in plans]
    if len(set(targets)) != len(targets):
        raise ValueError('Only one plan per repository and target branch in a batch')
    batch = {'schema': 1, 'kind': 'batch', 'plans': plans}
    batch['id'] = digest(batch)
    return batch


def approve_batch(batch, actor):
    if batch['id'] != digest(batch) or not actor.strip():
        raise ValueError('Batch changed or approver missing')
    for plan in batch['plans']:
        verify_plan(plan)
    batch['approval'] = {'by': actor.strip(), 'plan_id': batch['id'],
                         'at': datetime.now(timezone.utc).isoformat()}
    return batch


def apply_batch(batch, workers=4):
    approval = batch.get('approval', {})
    if (batch['id'] != digest(batch) or approval.get('plan_id') != batch['id']
            or not approval.get('by')):
        raise ValueError('Approval of this exact batch is required')

    def run(original):
        plan = copy.deepcopy(original)
        plan['approval'] = dict(approval, plan_id=plan['id'])
        try:
            return dict(apply(plan), repo=plan['repo'], target_branch=plan['target_branch'])
        except (ValueError, KeyError, OSError, ET.ParseError, subprocess.CalledProcessError) as error:
            return {'plan_id': plan['id'], 'repo': plan['repo'],
                    'target_branch': plan['target_branch'], 'status': 'failed', 'error': str(error)}

    with ThreadPoolExecutor(max_workers=max(1, min(20, workers))) as executor:
        results = list(executor.map(run, batch['plans']))
    return {'batch_id': batch['id'], 'results': results, 'simulated_gitlab': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    plan_parser = commands.add_parser('plan')
    plan_parser.add_argument('--repo', required=True)
    plan_parser.add_argument('--target', choices=POLICIES, required=True)
    plan_parser.add_argument('--changes', required=True, help='JSON file with a list of changes')
    plan_parser.add_argument('--out', required=True)
    approve_parser = commands.add_parser('approve')
    approve_parser.add_argument('plan')
    approve_parser.add_argument('--by', required=True)
    apply_parser = commands.add_parser('apply')
    apply_parser.add_argument('plan')
    batch_parser = commands.add_parser('batch-plan')
    batch_parser.add_argument('--config', required=True, help='JSON list of repo/target/changes/selected entries')
    batch_parser.add_argument('--out', required=True)
    batch_apply = commands.add_parser('batch-apply')
    batch_apply.add_argument('plan')
    batch_apply.add_argument('--workers', type=int, default=4)
    batch_apply.add_argument('--out', required=True, help='Persistent batch result JSON')
    args = parser.parse_args()
    try:
        if args.command == 'plan':
            plan = create_plan(args.repo, args.target, json.loads(Path(args.changes).read_text()))
            Path(args.out).write_text(json.dumps(plan, indent=2) + '\n')
            print('Plan written to ' + args.out)
        elif args.command == 'batch-plan':
            batch = create_batch(json.loads(Path(args.config).read_text()))
            Path(args.out).write_text(json.dumps(batch, indent=2) + '\n')
            print('Batch written to ' + args.out)
        elif args.command == 'approve':
            path = Path(args.plan)
            content = json.loads(path.read_text())
            plan = (approve_batch if content.get('kind') == 'batch' else approve)(content, args.by)
            path.write_text(json.dumps(plan, indent=2) + '\n')
            print('Approved ' + plan['id'])
        elif args.command == 'batch-apply':
            result = apply_batch(json.loads(Path(args.plan).read_text()), args.workers)
            Path(args.out).write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(apply(json.loads(Path(args.plan).read_text())), indent=2))
    except (ValueError, KeyError, ET.ParseError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
