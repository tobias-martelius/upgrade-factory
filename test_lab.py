import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import lab


class LabTest(unittest.TestCase):
    def test_local_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = lab.DATA, lab.STATE
            lab.DATA = Path(directory)
            lab.STATE = lab.DATA / 'state.json'
            server = None
            try:
                lab.bootstrap()
                lab.bootstrap()  # Initialization must preserve existing state.
                lab.prepare_upgrade_fixtures()
                fixture = lab.DATA / 'repos/order-service'
                prepared_head = lab.git(fixture, 'rev-parse', 'main')
                lab.prepare_upgrade_fixtures()
                self.assertEqual(lab.git(fixture, 'rev-parse', 'main'), prepared_head)
                self.assertEqual(lab.git(fixture, 'rev-parse', 'develop'), prepared_head)
                self.assertTrue((fixture / 'src/test/java/lab/AppTest.java').exists())
                self.assertIn('maven-surefire-plugin', (fixture / 'pom.xml').read_text())
                server = lab.ThreadingHTTPServer(('127.0.0.1', 0), lab.Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()

                def request(path, data=None):
                    body = None if data is None else json.dumps(data).encode()
                    req = Request(f'http://127.0.0.1:{server.server_port}/api/v4/{path}',
                                  data=body, headers={'Content-Type': 'application/json'})
                    with urlopen(req) as response:
                        return json.load(response)

                projects = request('projects')
                self.assertEqual(len(projects), 20)
                self.assertEqual(len(request('projects?per_page=3&page=2')), 3)
                self.assertTrue((Path(projects[0]['local_path']) / 'pom.xml').exists())
                branch = request('projects/1/repository/branches', {'branch': 'upgrade/batch-1'})
                self.assertEqual(branch['name'], 'upgrade/batch-1')
                mr = request('projects/1/merge_requests', {
                    'title': 'Batch 1', 'source_branch': 'upgrade/batch-1', 'target_branch': 'main'})
                self.assertTrue(mr['simulated'])
                self.assertIsNone(mr['head_pipeline'])
                self.assertEqual(request('projects/1/merge_requests')[0]['iid'], 1)
                issue = request('projects/1/issues', {'title': 'Build failed'})
                self.assertEqual(issue['state'], 'opened')
                with self.assertRaises(HTTPError) as error:
                    request('projects/999')
                self.assertEqual(error.exception.code, 404)
            finally:
                if server:
                    server.shutdown()
                    server.server_close()
                    thread.join()
                lab.DATA, lab.STATE = previous


if __name__ == '__main__':
    unittest.main()
