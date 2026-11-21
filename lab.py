#!/usr/bin/env python3
"""Local GitLab-shaped development fixture; not a GitLab implementation."""
import argparse
import json
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import RLock
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
DATA = ROOT / '.lab'
STATE = DATA / 'state.json'
LOCK = RLock()
NAMES = ['order', 'customer', 'inventory', 'payment', 'shipping', 'notification',
         'catalog', 'pricing', 'discount', 'invoice', 'report', 'search', 'auth',
         'audit', 'booking', 'subscription', 'document', 'integration', 'batch', 'health']
SCENARIOS = ['simple-upgrade', 'simple-upgrade', 'multiple-findings', 'test-failure',
             'simple-upgrade', 'transitive-dependency', 'multiple-upgrades', 'major-upgrade',
             'simple-upgrade', 'compile-failure', 'document-library', 'transitive-dependency',
             'code-change', 'clean-baseline', 'simple-upgrade', 'multiple-upgrades',
             'file-library', 'version-conflict', 'existing-build-failure', 'clean-baseline']


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


def save(state):
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(STATE)


def bootstrap():
    DATA.mkdir(exist_ok=True)
    if STATE.exists():
        return
    projects = []
    for number, (name, scenario) in enumerate(zip(NAMES, SCENARIOS), 1):
        slug = name + '-service'
        path = DATA / 'repos' / slug
        path.mkdir(parents=True, exist_ok=True)
        source = path / 'src/main/java/lab/App.java'
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('package lab;\npublic class App {\n'
                          '    public static void main(String[] args) {\n'
                          f'        System.out.println("{slug}");\n'
                          '    }\n}\n')
        (path / 'pom.xml').write_text(f'''<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>lab</groupId><artifactId>{slug}</artifactId><version>1.0.0</version>
  <properties><maven.compiler.release>21</maven.compiler.release></properties>
  <build><plugins><plugin>
    <groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId>
    <version>3.13.0</version>
  </plugin></plugins></build>
</project>
''')
        (path / 'README.md').write_text(f'# {slug}\n\nLocal Java 21 fixture.\n')
        git(path, 'init', '-b', 'main')
        git(path, 'add', '.')
        git(path, '-c', 'user.name=Upgrade Lab', '-c', 'user.email=lab@example.invalid',
            '-c', 'commit.gpgsign=false', 'commit', '-m', 'Initial Java fixture')
        projects.append({'id': number, 'name': slug, 'path_with_namespace': 'upgrade-lab/' + slug,
                         'default_branch': 'main', 'ssh_url_to_repo': None,
                         'http_url_to_repo': None, 'local_path': str(path),
                         'lab_scenario': scenario})
    save({'projects': projects, 'merge_requests': {}, 'issues': {}})


def prepare_upgrade_fixtures():
    """Add dependency, real test and develop to pristine generated fixtures."""
    state = json.loads(STATE.read_text())
    for project in state['projects']:
        path = Path(project['local_path'])
        if git(path, 'status', '--porcelain') or git(path, 'branch', '--show-current') != 'main':
            raise ValueError('Fixture must be clean and checked out on main: ' + str(path))
        previous_main = git(path, 'rev-parse', 'main')
        pom = path / 'pom.xml'
        text = pom.read_text()
        if '<dependencies>' not in text:
            text = text.replace('  <build>', '''  <dependencies><dependency>
    <groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>
    <version>3.12.0</version>
  </dependency></dependencies>
  <build>''')
        if '<artifactId>junit</artifactId>' not in text:
            text = text.replace('</dependencies>', '''<dependency>
    <groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version>
    <scope>test</scope>
  </dependency></dependencies>''', 1)
        if '<artifactId>maven-surefire-plugin</artifactId>' not in text:
            text = text.replace('</plugins>', '''<plugin>
    <groupId>org.apache.maven.plugins</groupId><artifactId>maven-surefire-plugin</artifactId>
    <version>3.5.2</version>
  </plugin></plugins>''', 1)
        pom.write_text(text)
        test = path / 'src/test/java/lab/AppTest.java'
        if not test.exists():
            test.parent.mkdir(parents=True, exist_ok=True)
            test.write_text('package lab;\nimport org.junit.Test;\n'
                            'public class AppTest {\n'
                            '    @Test public void starts() { App.main(new String[0]); }\n}\n')
        ignore = path / '.gitignore'
        if not ignore.exists():
            ignore.write_text('target/\n')
        if git(path, 'status', '--porcelain'):
            git(path, 'add', '--', 'pom.xml', 'src/test', '.gitignore')
            git(path, '-c', 'user.name=Upgrade Lab', '-c', 'user.email=lab@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-m', 'Prepare upgrade and verification fixtures')
        branches = git(path, 'for-each-ref', '--format=%(refname:short)', 'refs/heads').splitlines()
        if 'develop' not in branches:
            git(path, 'branch', 'develop', 'main')
        elif git(path, 'rev-parse', 'develop') == previous_main:
            # Only advance a pristine fixture branch with no independent changes.
            git(path, 'update-ref', 'refs/heads/develop', git(path, 'rev-parse', 'main'), previous_main)


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.dispatch('GET')

    def do_POST(self):
        self.dispatch('POST')

    def dispatch(self, method):
        try:
            with LOCK:
                self.handle_request(method)
        except (ValueError, KeyError, subprocess.CalledProcessError) as error:
            self.reply(400, {'message': str(error)})

    def handle_request(self, method):
        url = urlparse(self.path)
        state = json.loads(STATE.read_text())
        if method == 'GET' and url.path == '/api/v4/projects':
            query = parse_qs(url.query)
            projects = state['projects']
            if query.get('search'):
                projects = [p for p in projects if query['search'][0].lower() in p['name'].lower()]
            page = max(1, int(query.get('page', ['1'])[0]))
            size = max(1, min(100, int(query.get('per_page', ['20'])[0])))
            return self.reply(200, projects[(page - 1) * size:page * size])
        match = re.fullmatch(r'/api/v4/projects/([^/]+)(?:/(.*))?', url.path)
        if not match:
            return self.reply(404, {'message': 'Unsupported endpoint'})
        identifier, resource = unquote(match[1]), match[2]
        project = next((p for p in state['projects']
                        if str(p['id']) == identifier or p['path_with_namespace'] == identifier), None)
        if project is None:
            return self.reply(404, {'message': 'Project not found'})
        path = Path(project['local_path'])
        key = str(project['id'])
        if method == 'GET' and resource is None:
            return self.reply(200, project)
        if method == 'GET' and resource == 'repository/branches':
            names = git(path, 'for-each-ref', '--format=%(refname:short)', 'refs/heads').splitlines()
            return self.reply(200, [{'name': n, 'commit': {'id': git(path, 'rev-parse', n)}} for n in names])
        if resource not in ('repository/branches', 'merge_requests', 'issues'):
            return self.reply(404, {'message': 'Unsupported endpoint'})
        if method == 'GET' and resource != 'repository/branches':
            return self.reply(200, state[resource].get(key, []))
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1_000_000:
            return self.reply(413, {'message': 'Request too large'})
        payload = json.loads(self.rfile.read(length) or '{}')
        if resource == 'repository/branches':
            branch, ref = payload['branch'], payload.get('ref', 'main')
            git(path, 'check-ref-format', '--branch', branch)
            commit = git(path, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}')
            git(path, 'branch', '--', branch, commit)
            return self.reply(201, {'name': branch, 'commit': {'id': commit}})
        if not payload.get('title'):
            return self.reply(400, {'message': 'title is required'})
        if resource == 'merge_requests':
            for field in ('source_branch', 'target_branch'):
                branch = payload[field]
                git(path, 'show-ref', '--verify', 'refs/heads/' + branch)
            if payload['source_branch'] == payload['target_branch']:
                return self.reply(400, {'message': 'Branches must differ'})
        items = state[resource].setdefault(key, [])
        item = {k: payload[k] for k in ('title', 'description', 'source_branch', 'target_branch') if k in payload}
        item.update({'iid': len(items) + 1, 'project_id': project['id'], 'state': 'opened', 'simulated': True})
        if resource == 'merge_requests':
            item['head_pipeline'] = None
        items.append(item)
        save(state)
        return self.reply(201, item)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'prepare', 'serve'])
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--host', default='127.0.0.1', help='Use 0.0.0.0 only inside the container')
    args = parser.parse_args()
    bootstrap()
    if args.command == 'init':
        print(f'Created or reused 20 repositories in {DATA / "repos"}')
    elif args.command == 'prepare':
        prepare_upgrade_fixtures()
        print('Prepared version-update fixtures and develop branches')
    else:
        try:
            server = ThreadingHTTPServer((args.host, args.port), Handler)
        except OSError as error:
            parser.exit(1, f'Cannot listen on {args.host}:{args.port}: {error}\n'
                           'Try another port: python3 lab.py serve --port 8081\n')
        print(f'Simulated GitLab API: http://{args.host}:{server.server_port}/api/v4', flush=True)
        with server:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == '__main__':
    main()
