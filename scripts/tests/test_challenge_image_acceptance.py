"""Pure Docker-boundary contracts: no daemon, credentials or services are used."""
import dataclasses
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RUNNER = Path(__file__).resolve().parents[1] / 'challenge-image-acceptance.py'
module = None
if RUNNER.exists():
    loader = importlib.util.spec_from_file_location('challenge_image_acceptance', RUNNER)
    module = importlib.util.module_from_spec(loader)
    sys.modules[loader.name] = module
    loader.loader.exec_module(module)

DIGEST = 'sha256:' + 'a' * 64
DAEMON_ID = 'sha256:' + 'b' * 64
CLIENT_ID = 'sha256:' + 'c' * 64
DEP_ID = 'sha256:' + 'd' * 64


def spec_dict(directory):
    return dict(schema_version=1, source_sha='1' * 40, workflow_sha='1' * 40,
                tooling_sha='1' * 40, workflow_run=123, workflow_attempt=1,
                image_ref='ghcr.io/synthetic/keycast@' + DIGEST,
                platform_manifest_digest='sha256:' + 'e' * 64,
                registry_config_digest=DIGEST, daemon_image_id=DAEMON_ID,
                test_client_image_id=CLIENT_ID,
                dependencies={'postgres': 'postgres@' + DIGEST,
                              'redis': 'redis@' + DIGEST,
                              'relay_builder': 'ghcr.io/synthetic/relay_builder@' + DIGEST},
                evidence_dir=str(directory))


class DockerBoundary:
    """Models only local Docker CLI operations; unexpected commands fail the test."""
    def __init__(self, sabotage=None):
        self.calls = []
        self.containers = {}
        self.networks = {}
        self.sabotage = sabotage
        self.removed = []
        self.summary = {'schema_version': 1, 'cases': []}

    def __call__(self, argv, env, timeout):
        assert isinstance(argv, list) and all(isinstance(x, str) for x in argv)
        assert 0 < timeout <= 900
        self.calls.append((argv, env, timeout))
        if self.sabotage == 'timeout' and 'node_modules/@playwright/test/cli.js' in argv:
            raise subprocess.TimeoutExpired(argv, timeout, output='PRIVATE CHILD BODY')
        if self.sabotage == 'sigterm' and 'psql' in argv:
            os.kill(os.getpid(), signal.SIGTERM)
        code, output = 0, ''
        if argv[1:3] == ['image', 'inspect']:
            ref = argv[-1]
            ident = CLIENT_ID if ref == CLIENT_ID else DAEMON_ID if 'keycast@' in ref else DEP_ID
            if self.sabotage == 'wrong-image' and 'keycast@' in ref:
                ident = DEP_ID
            output = json.dumps([{'Id': ident, 'Os': 'linux', 'Architecture': 'amd64',
                                  'RepoDigests': [ref], 'Config': {'Env': []}}])
        elif argv[1:3] == ['network', 'create']:
            ident = 'f' * 64
            label = argv[argv.index('--label') + 1]
            self.networks[ident] = {'Id': ident, 'Name': argv[-1], 'Internal': True,
                                   'Labels': dict([label.split('=', 1)]), 'Containers': {}}
            output = ident
        elif argv[1:3] == ['network', 'inspect']:
            target = argv[-1]
            item = self.networks.get(target) or next((n for n in self.networks.values() if n['Name'] == target), None)
            if item:
                item = dict(item)
                if self.sabotage == 'foreign-network':
                    item['Labels'] = {}
                if self.sabotage == 'public-network':
                    item['Internal'] = False
                output = json.dumps([item])
            else:
                code, output = 1, '[]'
        elif argv[1] == 'create':
            name = argv[argv.index('--name') + 1]
            image_index = next(i for i, value in enumerate(argv) if value.startswith(('postgres@', 'redis@', 'ghcr.io/', 'sha256:')))
            ref = argv[image_index]
            network = argv[argv.index('--network') + 1]
            labels = dict([argv[argv.index('--label') + 1].split('=', 1)])
            ident = f'{len(self.containers) + 1:064x}'
            mounts = []
            for i, value in enumerate(argv):
                if value == '--mount':
                    fields = dict(x.split('=', 1) for x in argv[i + 1].split(',') if '=' in x)
                    mounts.append({'Type': fields['type'], 'Source': fields['src'],
                                   'Destination': fields['dst'], 'RW': False})
                if value == '--tmpfs':
                    mounts.append({'Type': 'tmpfs', 'Destination': argv[i + 1].split(':')[0], 'RW': True})
            effective_env = []
            for i, value in enumerate(argv):
                if value == '--env':
                    effective_env.append(argv[i + 1])
                if value == '--env-file':
                    effective_env.extend(Path(argv[i + 1]).read_text().splitlines())
            self.containers[ident] = {
                'Id': ident, 'Name': '/' + name,
                'Image': CLIENT_ID if ref == CLIENT_ID else DAEMON_ID if 'keycast@' in ref else DEP_ID,
                'Config': {'Labels': labels, 'Env': effective_env}, 'Mounts': mounts,
                'HostConfig': {'NetworkMode': network, 'PortBindings': {}, 'Privileged': False,
                               'PidMode': '', 'IpcMode': 'private', 'Binds': None,
                               'VolumesFrom': None, 'Devices': [], 'CapAdd': None},
                'State': {'Running': False},
                'NetworkSettings': {'Networks': {} if network.startswith('container:') else {self.networks[network]['Name']: {'NetworkID': ''}}, 'Ports': {}},
            }
            if '--cidfile' in argv:
                Path(argv[argv.index('--cidfile') + 1]).write_text(ident)
            output = ident
        elif argv[1] == 'inspect':
            target = argv[-1]
            item = self.containers.get(target) or next((c for c in self.containers.values() if c['Name'] == '/' + target), None)
            if item:
                item = json.loads(json.dumps(item))
                if self.sabotage == 'foreign-container':
                    item['Config']['Labels'] = {}
                if self.sabotage == 'volume':
                    item['Mounts'].append({'Type': 'volume', 'Source': '/old/data', 'Destination': '/data', 'RW': True})
                if self.sabotage == 'host-port':
                    item['HostConfig']['PortBindings'] = {'3000/tcp': [{'HostPort': '3000'}]}
                if self.sabotage == 'second-network':
                    item['NetworkSettings']['Networks']['bridge'] = {}
                if self.sabotage == 'container-image':
                    item['Image'] = DEP_ID
                output = json.dumps([item])
            else:
                code, output = 1, '[]'
        elif argv[1] == 'start':
            assert argv[-1] in self.containers
            self.containers[argv[-1]]['State']['Running'] = True
            for attachment in self.containers[argv[-1]]['NetworkSettings']['Networks'].values():
                attachment['NetworkID'] = self.containers[argv[-1]]['HostConfig']['NetworkMode']
        elif argv[1] == 'exec':
            if 'psql' in argv:
                output = '1\n'
            elif 'redis-cli' in argv:
                output = 'PONG\n'
            elif 'node' in argv:
                script = argv[-1]
                if 'generateSecretKey' in script and 'finalizeEvent' not in script:
                    output = '2' * 64
                elif 'readFileSync' in script:
                    output = json.dumps(self.summary)
            else:
                raise AssertionError(argv)
        elif argv[1] == 'wait':
            output = '0\n'
        elif argv[1] == 'rm':
            ident = argv[-1]
            if self.sabotage == 'cleanup':
                return subprocess.CompletedProcess(argv, 1, '', 'PRIVATE CHILD BODY')
            self.removed.append(ident)
            self.containers.pop(ident, None)
        elif argv[1:3] == ['network', 'rm']:
            self.removed.append(argv[-1])
            self.networks.pop(argv[-1], None)
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, code, output, 'PRIVATE CHILD BODY' if code else '')


class AcceptanceContracts(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(module, 'isolated acceptance runtime is not implemented')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'evidence'
        self.data = spec_dict(self.directory)

    def run_with(self, boundary=None):
        boundary = boundary or DockerBoundary()
        return module.run_acceptance(module.RunSpec.from_dict(self.data), boundary), boundary

    def test_tag_only_release_and_each_dependency_rejected_before_docker(self):
        for key in ('image_ref', 'postgres', 'redis', 'relay_builder'):
            with self.subTest(key=key):
                data = spec_dict(self.directory)
                if key == 'image_ref':
                    data[key] = 'ghcr.io/synthetic/keycast:latest'
                else:
                    data['dependencies'][key] = 'synthetic:latest'
                with self.assertRaises(ValueError):
                    module.RunSpec.from_dict(data)

    def test_unknown_fields_and_production_url_rejected(self):
        for key, value in [('app_url', 'https://production.example'), ('expected_case_ids', ['anything']),
                           ('environment', {'DATABASE_URL': 'postgres://production.example/live'})]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.RunSpec.from_dict({**self.data, key: value})

    def test_source_mismatch_and_invalid_id_rejected(self):
        for key, value in [('workflow_sha', '2' * 40), ('daemon_image_id', 'keycast:latest'),
                           ('workflow_attempt', 0), ('workflow_run', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.RunSpec.from_dict({**self.data, key: value})

    def test_wrong_pulled_daemon_id_stops_before_resources(self):
        result, docker = self.run_with(DockerBoundary('wrong-image'))
        self.assertFalse(result.passed)
        self.assertFalse(any(call[0][1] in ('create', 'exec') for call in docker.calls))

    def test_legitimate_daemon_id_differs_from_config_digest(self):
        result, docker = self.run_with()
        self.assertTrue(any('--migrate' in call[0] for call in docker.calls))
        self.assertFalse(result.passed)  # Future acceptance suite is absent.
        self.assertFalse(result.complete)
        self.assertTrue(result.cleanup['complete'])

    def test_foreign_ownership_and_storage_never_reach_fixture_or_migration(self):
        for sabotage in ('foreign-container', 'foreign-network', 'public-network', 'volume',
                         'host-port', 'second-network', 'container-image'):
            with self.subTest(sabotage=sabotage):
                self.data['evidence_dir'] = str(Path(self.temp.name) / sabotage)
                result, docker = self.run_with(DockerBoundary(sabotage))
                self.assertFalse(result.passed)
                self.assertFalse(any('--migrate' in call[0] or 'exec' == call[0][1] for call in docker.calls))

    def test_preexisting_name_collision_is_never_adopted_or_removed(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def collide(argv, env, timeout):
            if argv[1:3] == ['network', 'inspect'] and argv[-1].startswith('keycast-acceptance-'):
                return subprocess.CompletedProcess(argv, 0, json.dumps([{'Id': '9' * 64}]), '')
            return original(docker, argv, env, timeout)
        result, _ = self.run_with(collide)
        self.assertFalse(result.passed)
        self.assertEqual(docker.removed, [])

    def test_runtime_topology_timeouts_environment_and_secrets(self):
        with patch.dict(os.environ, {'AWS_SECRET_ACCESS_KEY': 'INHERITED_SECRET',
                                    'DATABASE_URL': 'postgres://production.example/live',
                                    'DOCKER_HOST': 'tcp://production.example:2375',
                                    'DOCKER_CONFIG': '/production/credentials'}):
            result, docker = self.run_with()
        creates = [argv for argv, _, _ in docker.calls if argv[1] == 'create']
        owner = next(a for a in creates if any(v.startswith('postgres@') for v in a))
        self.assertIn('--tmpfs', owner)
        client = next(a for a in creates if CLIENT_ID in a)
        self.assertTrue(any(v.startswith('/tmp:') for v in client))
        for argv, env, timeout in docker.calls:
            self.assertNotIn('INHERITED_SECRET', repr(env))
            self.assertNotIn('DOCKER_HOST', env)
            self.assertNotIn('DATABASE_URL', env)
            self.assertIn('DOCKER_CONFIG', env)
            self.assertNotEqual(env['DOCKER_CONFIG'], '/production/credentials')
            self.assertNotIn('--publish', argv)
            self.assertNotIn('-p', argv)
            self.assertNotIn('/var/run/docker.sock', repr(argv))
            self.assertNotIn('production.example', repr(argv))
            self.assertGreater(timeout, 0)
        for argv in creates:
            network = argv[argv.index('--network') + 1]
            if argv is not owner:
                self.assertRegex(network, r'^container:[0-9a-f]{64}$')
        migrate = next(a for a in creates if '--migrate' in a)
        self.assertEqual(migrate[migrate.index('--entrypoint') + 1], '/app/keycast')
        serving = next(a for a in creates if any(v.startswith('ghcr.io/synthetic/keycast@') for v in a) and '--migrate' not in a)
        self.assertNotIn('--entrypoint', serving)
        self.assertTrue(any('node_modules/@playwright/test/cli.js' in a and 'challenge-image.config.ts' in a for a, _, _ in docker.calls))
        self.assertTrue(any('psql' in a and 'SELECT 1' in a and '--host=localhost' in a and '--port=5432' in a for a, _, _ in docker.calls))
        self.assertTrue(any('redis-cli' in a and 'PING' in a for a, _, _ in docker.calls))
        self.assertFalse(list(self.directory.glob('.private-*')))
        self.assertNotIn('PRIVATE CHILD BODY', json.dumps(dataclasses.asdict(result)))

    def test_incomplete_duplicate_unknown_and_failed_cases_fail_closed(self):
        for cases in ([], [{'id': 'unknown', 'passed': True}],
                      [{'id': 'signing.http', 'passed': True}] * 2,
                      [{'id': 'signing.http', 'passed': False}]):
            with self.subTest(cases=cases):
                docker = DockerBoundary()
                docker.summary['cases'] = cases
                self.data['evidence_dir'] = str(Path(self.temp.name) / str(len(docker.calls)) / str(len(repr(cases))))
                result, _ = self.run_with(docker)
                self.assertFalse(result.passed)
                self.assertFalse(result.complete)

    def test_timeout_cleans_up_without_raw_output(self):
        result, docker = self.run_with(DockerBoundary('timeout'))
        self.assertFalse(result.passed)
        self.assertTrue(result.cleanup['complete'])
        self.assertGreater(len(docker.removed), 3)
        self.assertNotIn('PRIVATE CHILD BODY', json.dumps(dataclasses.asdict(result)))

    def test_sigterm_is_caught_and_cleanup_runs(self):
        result, docker = self.run_with(DockerBoundary('sigterm'))
        self.assertFalse(result.passed)
        self.assertTrue(result.cleanup['complete'])
        self.assertGreater(len(docker.removed), 3)
        self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_cleanup_failure_prevents_success_and_journal_can_be_retried(self):
        result, docker = self.run_with(DockerBoundary('cleanup'))
        self.assertFalse(result.passed)
        self.assertFalse(result.cleanup['complete'])
        docker.sabotage = None
        status = module.cleanup_owned(self.directory / 'ownership.json', docker)
        self.assertTrue(status['complete'])
        before = list(docker.removed)
        self.assertTrue(module.cleanup_owned(self.directory / 'ownership.json', docker)['complete'])
        self.assertEqual(before, docker.removed)

    def test_cleanup_uses_only_recorded_ids_in_consumer_owner_network_order(self):
        _, docker = self.run_with()
        journal = json.loads((self.directory / 'ownership.json').read_text())
        ids = [r['id'] for r in journal['resources']]
        self.assertEqual(set(docker.removed), set(ids))
        self.assertEqual(docker.removed[-1], next(r['id'] for r in journal['resources'] if r['kind'] == 'network'))
        self.assertEqual(docker.removed[-2], next(r['id'] for r in journal['resources'] if r['role'] == 'postgres'))
        self.assertFalse(any('--filter' in a for a, _, _ in docker.calls))

    def test_cleanup_rejects_unknown_journal_fields_and_foreign_labels(self):
        _, docker = self.run_with(DockerBoundary('cleanup'))
        journal_path = self.directory / 'ownership.json'
        journal = json.loads(journal_path.read_text())
        journal['unknown'] = True
        journal_path.write_text(json.dumps(journal))
        with self.assertRaises(ValueError):
            module.cleanup_owned(journal_path, docker)
        del journal['unknown']
        journal_path.write_text(json.dumps(journal))
        docker.sabotage = 'foreign-container'
        result = module.cleanup_owned(journal_path, docker)
        self.assertFalse(result['complete'])
        self.assertEqual(docker.removed, [])

    def test_all_source_owned_cases_must_execute_and_cleanup_to_pass(self):
        docker = DockerBoundary()
        docker.summary['cases'] = [
            {'id': 'signing.http', 'passed': True},
            {'id': 'signing.nip46', 'passed': True},
            {'id': 'consent.authorize', 'passed': True},
            {'id': 'consent.refresh', 'passed': True},
            {'id': 'management.creation-held', 'passed': True},
        ]
        result, _ = self.run_with(docker)
        self.assertTrue(result.complete)
        self.assertTrue(result.passed)
        self.assertEqual(result.counts, {'expected': 9, 'executed': 9, 'passed': 9, 'failed': 0})
        self.data['evidence_dir'] = str(Path(self.temp.name) / 'failed-case')
        docker = DockerBoundary()
        docker.summary['cases'] = [
            {'id': 'signing.http', 'passed': False},
            {'id': 'signing.nip46', 'passed': True},
            {'id': 'consent.authorize', 'passed': True},
            {'id': 'consent.refresh', 'passed': True},
            {'id': 'management.creation-held', 'passed': True},
        ]
        result, _ = self.run_with(docker)
        self.assertTrue(result.complete)
        self.assertFalse(result.passed)
        self.assertEqual(result.counts['failed'], 1)

    def test_incomplete_suite_does_not_discard_executed_case_evidence(self):
        docker = DockerBoundary()
        docker.summary['cases'] = [{'id': 'signing.http', 'passed': True}]
        result, _ = self.run_with(docker)
        self.assertFalse(result.complete)
        self.assertFalse(result.passed)
        self.assertIn('signing.http', result.executed_case_ids)

    def test_unexpected_image_environment_is_rejected_before_network(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def credentials(argv, env, timeout):
            reply = original(docker, argv, env, timeout)
            if argv[1:3] == ['image', 'inspect']:
                data = json.loads(reply.stdout)
                data[0]['Config']['Env'] = ['AWS_SECRET_ACCESS_KEY=PRIVATE CHILD BODY']
                reply.stdout = json.dumps(data)
            return reply
        result, _ = self.run_with(credentials)
        self.assertFalse(result.passed)
        self.assertFalse(docker.networks)
        self.assertFalse(any('--migrate' in a for a, _, _ in docker.calls))

    def test_dependency_pulled_reference_must_match_requested_digest(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def wrong_reference(argv, env, timeout):
            reply = original(docker, argv, env, timeout)
            if argv[1:3] == ['image', 'inspect'] and argv[-1].startswith('postgres@'):
                data = json.loads(reply.stdout)
                data[0]['RepoDigests'] = ['postgres@sha256:' + '9' * 64]
                reply.stdout = json.dumps(data)
            return reply
        result, _ = self.run_with(wrong_reference)
        self.assertFalse(result.passed)
        self.assertFalse(any(a[1:3] == ['network', 'create'] for a, _, _ in docker.calls))

    def test_hanging_real_executor_is_killed_and_diagnostics_remain_private(self):
        private = Path(self.temp.name) / 'private'
        private.mkdir(mode=0o700)
        execute = module.SubprocessExecutor(private)
        with self.assertRaises(subprocess.TimeoutExpired):
            execute([sys.executable, '-c', "import time;print('PRIVATE CHILD BODY',flush=True);time.sleep(10)"], {}, 0.05)
        self.assertEqual((private / 'child.out').stat().st_mode & 0o777, 0o600)
        self.assertEqual((private / 'child.err').stat().st_mode & 0o777, 0o600)

    def test_creation_timeout_after_daemon_create_recovers_recorded_owned_id(self):
        for kind in ('network', 'container'):
            with self.subTest(kind=kind):
                self.data['evidence_dir'] = str(Path(self.temp.name) / kind)
                docker = DockerBoundary()
                original = docker.__class__.__call__
                fired = False
                def interrupted(argv, env, timeout):
                    nonlocal fired
                    reply = original(docker, argv, env, timeout)
                    if not fired and ((kind == 'network' and argv[1:3] == ['network', 'create']) or
                                      (kind == 'container' and argv[1] == 'create')):
                        fired = True
                        raise subprocess.TimeoutExpired(argv, timeout)
                    return reply
                result, _ = self.run_with(interrupted)
                self.assertFalse(result.passed)
                self.assertTrue(result.cleanup['complete'])
                self.assertEqual(len(docker.removed), 1 if kind == 'network' else 2)
                journal = json.loads((Path(self.data['evidence_dir']) / 'ownership.json').read_text())
                self.assertEqual(set(docker.removed), {r['id'] for r in journal['resources']})

    def test_forged_pending_intent_and_foreign_cidfile_never_remove_resources(self):
        _, docker = self.run_with(DockerBoundary('cleanup'))
        path = self.directory / 'ownership.json'
        journal = json.loads(path.read_text())
        journal['pending'] = [{'kind': 'container', 'role': 'server', 'name': 'production-server'}]
        path.write_text(json.dumps(journal))
        with self.assertRaises(ValueError):
            module.cleanup_owned(path, docker)
        self.assertEqual(docker.removed, [])

    def test_foreign_recovery_cidfile_and_labels_cannot_grant_cleanup_ownership(self):
        for sabotage in ('cidfile', 'labels'):
            with self.subTest(sabotage=sabotage):
                self.data['evidence_dir'] = str(Path(self.temp.name) / sabotage)
                docker = DockerBoundary()
                original = docker.__class__.__call__
                fired = False
                def interrupted(argv, env, timeout):
                    nonlocal fired
                    reply = original(docker, argv, env, timeout)
                    if not fired and argv[1] == 'create':
                        fired = True
                        if sabotage == 'cidfile':
                            Path(argv[argv.index('--cidfile') + 1]).write_text('9' * 64)
                        else:
                            docker.containers[reply.stdout]['Config']['Labels'] = {}
                        raise subprocess.TimeoutExpired(argv, timeout)
                    return reply
                result, _ = self.run_with(interrupted)
                self.assertFalse(result.passed)
                self.assertFalse(result.cleanup['complete'])
                self.assertEqual(docker.removed, [])

    def test_cleanup_timeout_after_delete_remains_idempotent(self):
        _, docker = self.run_with(DockerBoundary('cleanup'))
        docker.sabotage = None
        original = docker.__class__.__call__
        fired = False
        def interrupted(argv, env, timeout):
            nonlocal fired
            reply = original(docker, argv, env, timeout)
            if not fired and argv[1] == 'rm':
                fired = True
                raise subprocess.TimeoutExpired(argv, timeout)
            return reply
        path = self.directory / 'ownership.json'
        status = module.cleanup_owned(path, interrupted)
        self.assertFalse(status['complete'])
        self.assertTrue(module.cleanup_owned(path, docker)['complete'])
        self.assertEqual(len(docker.removed), len(set(docker.removed)))

    def test_attestation_is_derived_after_ownership_and_before_suite(self):
        _, docker = self.run_with()
        handoffs = [a for a, _, _ in docker.calls if len(a) >= 2 and 'writeFileSync' in a[-2]]
        self.assertEqual(len(handoffs), 1)
        handoff = handoffs[0]
        attestation = json.loads(handoff[-1])
        self.assertEqual(set(attestation), {
            'schema_version', 'nonce', 'source_sha', 'daemon_image_id',
            'namespace_owner_id', 'client_id', 'database_url', 'base_url', 'relay_url'})
        self.assertEqual(attestation['schema_version'], 1)
        self.assertEqual(attestation['daemon_image_id'], DAEMON_ID)
        self.assertEqual(attestation['source_sha'], '1' * 40)
        self.assertRegex(attestation['nonce'], r'^[0-9a-f]{32}$')
        self.assertEqual(attestation['base_url'], 'http://localhost:3000')
        self.assertEqual(attestation['relay_url'], 'ws://localhost:8080')
        self.assertEqual(attestation['database_url'], 'postgres://postgres:acceptance@localhost:5432/keycast_image_acceptance')
        self.assertNotIn('SERVER_NSEC', repr(attestation))
        calls = [a for a, _, _ in docker.calls]
        self.assertLess(calls.index(handoff), next(i for i, a in enumerate(calls) if 'node_modules/@playwright/test/cli.js' in a))

    def test_cleanup_failed_full_suite_cannot_emit_passed_true(self):
        docker = DockerBoundary('cleanup')
        docker.summary['cases'] = [
            {'id': 'signing.http', 'passed': True},
            {'id': 'signing.nip46', 'passed': True},
            {'id': 'consent.authorize', 'passed': True},
            {'id': 'consent.refresh', 'passed': True},
            {'id': 'management.creation-held', 'passed': True},
        ]
        result, _ = self.run_with(docker)
        self.assertTrue(result.complete)
        self.assertFalse(result.passed)
        self.assertFalse(result.cleanup['complete'])
        self.assertFalse(json.loads((self.directory / 'acceptance.json').read_text())['passed'])

    def test_unacknowledged_create_without_visible_resource_keeps_intent_and_fails_cleanup(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def interrupted(argv, env, timeout):
            if argv[1:3] == ['network', 'create']:
                raise subprocess.TimeoutExpired(argv, timeout)
            return original(docker, argv, env, timeout)
        result, _ = self.run_with(interrupted)
        self.assertFalse(result.passed)
        self.assertFalse(result.cleanup['complete'])
        journal = json.loads((self.directory / 'ownership.json').read_text())
        self.assertEqual(len(journal['pending']), 1)
        self.assertEqual(docker.removed, [])

    def test_late_client_ownership_failure_prevents_attestation_and_suite(self):
        docker = DockerBoundary()
        original = docker.__class__.__call__
        def foreign(argv, env, timeout):
            reply = original(docker, argv, env, timeout)
            if argv[1] == 'inspect' and reply.returncode == 0:
                data = json.loads(reply.stdout)
                is_client = data[0]['Image'] == CLIENT_ID
                server_exists = any(c['Image'] == DAEMON_ID and not c['Name'].endswith('-migration') for c in docker.containers.values())
                if is_client and server_exists:
                    data[0]['Config']['Labels'] = {}
                    reply.stdout = json.dumps(data)
            return reply
        result, _ = self.run_with(foreign)
        self.assertFalse(result.passed)
        self.assertFalse(any('writeFileSync' in repr(a) or 'node_modules/@playwright/test/cli.js' in a for a, _, _ in docker.calls))

    def test_invalid_cli_input_exits_nonzero_without_diagnostics(self):
        path = Path(self.temp.name) / 'spec.json'
        path.write_text(json.dumps({**self.data, 'secret': 'PRIVATE CHILD BODY'}))
        child = subprocess.run([sys.executable, str(RUNNER), '--spec', str(path)], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(child.returncode, 0)
        self.assertNotIn('PRIVATE CHILD BODY', child.stdout + child.stderr)
        self.assertNotIn('"passed": true', child.stdout)


if __name__ == '__main__':
    unittest.main()
