"""Persistent CycloneDX inventory, retaining repository/commit provenance."""
import argparse
import copy
import uuid
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def read_sbom(path):
    document = json.loads(Path(path).read_text())
    if document.get('bomFormat') != 'CycloneDX' or not document.get('specVersion'):
        raise ValueError('Expected CycloneDX JSON')
    if not isinstance(document.get('components', []), list):
        raise ValueError('Invalid CycloneDX components')
    return document


@contextmanager
def connect(database):
    Path(database).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(database), timeout=30)
    connection.execute('''CREATE TABLE IF NOT EXISTS snapshots (
        id TEXT PRIMARY KEY, repo TEXT NOT NULL, branch TEXT NOT NULL,
        commit_sha TEXT NOT NULL, role TEXT NOT NULL, recorded_at TEXT NOT NULL,
        document TEXT NOT NULL)''')
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def record(database, sbom, repo, branch, commit, role):
    if role not in ('baseline', 'candidate'):
        raise ValueError('Inventory role must be baseline or candidate')
    document = read_sbom(sbom)
    serialized = json.dumps(document, sort_keys=True)
    identity = hashlib.sha256(json.dumps([repo, branch, commit, role, serialized]).encode()).hexdigest()
    with connect(database) as connection:
        connection.execute('INSERT OR IGNORE INTO snapshots VALUES (?, ?, ?, ?, ?, ?, ?)',
                           (identity, repo, branch, commit, role,
                            datetime.now(timezone.utc).isoformat(), serialized))
    return identity


def export_inventory(database):
    with connect(database) as connection:
        rows = connection.execute('SELECT id, repo, branch, commit_sha, role, recorded_at, document '
                                  'FROM snapshots ORDER BY repo, branch, recorded_at, id').fetchall()
    return {'format': 'upgrade-lab-inventory-v1', 'snapshots': [
        {'id': row[0], 'repo': row[1], 'branch': row[2], 'commit': row[3],
         'role': row[4], 'recorded_at': row[5], 'sbom': json.loads(row[6])} for row in rows]}


def export_cyclonedx(database):
    """Aggregate snapshots without losing repo, branch, commit or role."""
    snapshots = export_inventory(database)['snapshots']
    applications = []
    dependencies = []
    for snapshot in snapshots:
        document = snapshot['sbom']
        prefix = 'urn:upgrade-lab:' + snapshot['id'] + ':'
        root = document.get('metadata', {}).get('component', {})
        root_ref = prefix + 'project'
        mapping = {}
        if root.get('bom-ref'):
            mapping[root['bom-ref']] = root_ref

        def clone_components(items):
            cloned = []
            for index, original in enumerate(items):
                component = copy.deepcopy(original)
                old_ref = component.get('bom-ref')
                # Hash avoids invalid characters and collisions between snapshots.
                new_ref = prefix + hashlib.sha256(json.dumps(original, sort_keys=True).encode()).hexdigest()
                if old_ref:
                    mapping[old_ref] = new_ref
                component['bom-ref'] = new_ref
                if component.get('components'):
                    component['components'] = clone_components(component['components'])
                cloned.append(component)
            return cloned

        children = clone_components(document.get('components', []))
        application = {'type': 'application', 'bom-ref': root_ref,
                       'name': snapshot['repo'], 'version': snapshot['commit'],
                       'properties': [{'name': 'upgrade-lab:' + key, 'value': snapshot[key]}
                                      for key in ('repo', 'branch', 'commit', 'role', 'id')],
                       'components': children}
        applications.append(application)
        graph = document.get('dependencies', [])
        for edge in graph:
            if edge.get('ref') not in mapping:
                continue
            dependencies.append({'ref': mapping[edge['ref']],
                                 'dependsOn': [mapping[ref] for ref in edge.get('dependsOn', [])
                                               if ref in mapping]})
        if not any(edge['ref'] == root_ref for edge in dependencies):
            dependencies.append({'ref': root_ref, 'dependsOn': [c['bom-ref'] for c in children]})
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6',
            'serialNumber': 'urn:uuid:' + str(uuid.uuid4()), 'version': 1,
            'metadata': {'timestamp': datetime.now(timezone.utc).isoformat()},
            'components': applications, 'dependencies': dependencies}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', default='.lab/inventory.sqlite')
    parser.add_argument('--out', required=True)
    parser.add_argument('--format', choices=['inventory', 'cyclonedx'], default='inventory')
    args = parser.parse_args()
    result = (export_cyclonedx if args.format == 'cyclonedx' else export_inventory)(args.database)
    Path(args.out).write_text(json.dumps(result, indent=2) + '\n')
    print('Exported inventory to ' + args.out)


if __name__ == '__main__':
    main()
